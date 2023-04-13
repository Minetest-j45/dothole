package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var upstream *string
var localPort *string

type cacheEntry struct {
	compress bool
	question dns.Question
	answer   dns.RR
	t        time.Time
}

type cache struct {
	sync.RWMutex
	entries map[dns.Question]cacheEntry
}

var cacheValidTime time.Duration = 10 * time.Second //todo: change to around 300 seconds

func loadList(list map[string]string, location string, url bool) {
	var raw []byte
	if url {
		resp, err := http.Get(location)
		if err != nil {
			log.Println("error getting list", location, err)
			return
		}
		defer resp.Body.Close()

		raw, _ = io.ReadAll(resp.Body)
	} else {
		raw, _ = os.ReadFile(location)
	}

	rawlines := strings.Split(string(raw), "\n")

	for _, line := range rawlines {
		parts := strings.Split(line, " ")
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" || len(parts) < 2 {
			continue
		}

		// add to list
		list[parts[1]+"."] = parts[0]
	}
}

func readPacket(conn net.Conn) ([]byte, []byte, error) {
	buf := make([]byte, 2)
	_, err := conn.Read(buf)
	if err != nil {
		return nil, nil, err
	}

	len := binary.BigEndian.Uint16(buf)
	if len > dns.MaxMsgSize {
		return nil, nil, errors.New("packet too long" + fmt.Sprint(len))
	}

	raw := make([]byte, len+2)
	copy(raw, buf)

	buf = make([]byte, len)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, nil, err
	}

	copy(raw[2:], buf)

	return raw, buf, nil
}

func handleConnection(localConn net.Conn, upstreamConn net.Conn, c *cache, list map[string]string) {
	go func() {
		for {
			raw, n, err := readPacket(localConn)
			if err != nil {
				log.Println("local read error", err)
				return
			}

			m := new(dns.Msg)
			err = m.Unpack(n)
			if err != nil {
				log.Println("dns unpack error", err)
				return
			}

			//check cache for the question
			response := new(dns.Msg)
			response.SetReply(m)
			anyCache := false

			c.Lock()
			for _, q := range m.Question {
				if entry, ok := c.entries[q]; ok {
					//check if cache entry is still valid
					if time.Since(entry.t) < cacheValidTime {
						anyCache = true
						response.Compress = response.Compress || entry.compress
						response.Answer = append(response.Answer, entry.answer)
					} else {
						delete(c.entries, q) //delete entry if it is not valid anymore
					}
				}
			}
			c.Unlock()

			if anyCache {
				if response.MsgHdr.RecursionDesired {
					response.MsgHdr.RecursionAvailable = true
				}

				responseRaw, err := response.Pack()
				if err != nil {
					log.Println("dns pack error", err)
					return
				}

				_, err = localConn.Write(append([]byte{byte(len(responseRaw) >> 8), byte(len(responseRaw))}, responseRaw...))
				if err != nil {
					log.Println("local write error", err)
					return
				}
			}

			if list != nil {
				response := new(dns.Msg)
				response.SetReply(m)
				anyBlock := false

				for _, q := range m.Question {
					//check blocklist for the question
					if ip, ok := list[q.Name]; ok {
						anyBlock = true
						log.Println("blocked:", q.Name, "to", ip)
						response.Answer = append(response.Answer, &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: q.Qtype,
								Class:  dns.ClassINET,
								Ttl:    0,
							},
							A: net.ParseIP(ip),
						})
					}
				}

				if anyBlock {
					if response.MsgHdr.RecursionDesired {
						response.MsgHdr.RecursionAvailable = true
					}

					responseRaw, err := response.Pack()
					if err != nil {
						log.Println("dns pack error", err)
						return
					}

					_, err = localConn.Write(append([]byte{byte(len(responseRaw) >> 8), byte(len(responseRaw))}, responseRaw...))
					if err != nil {
						log.Println("local write error", err)
						return
					}
				}
			}

			_, err = upstreamConn.Write(raw)
			if err != nil {
				log.Println("upstream write error", err)
				return
			}
		}
	}()

	for {
		raw, n, err := readPacket(upstreamConn)
		if err != nil {
			log.Println("upstream read error", err)
			return
		}

		m := new(dns.Msg)
		err = m.Unpack(n)
		if err != nil {
			log.Println("dns unpack error", err)
			return
		}

		if len(m.Answer) != 0 {
			c.Lock()
			for j, question := range m.Question {
				//add to cache
				c.entries[question] = cacheEntry{m.Compress, question, m.Answer[j], time.Now()}
			}
			c.Unlock()
		}

		_, err = localConn.Write(raw)
		if err != nil {
			log.Println("local write error", err)
			return
		}
	}
}

func main() {
	upstream = flag.String("upstream", "208.67.220.220:853", "upstream DNS over TLS server to use, format is ipaddr:port")
	localPort = flag.String("local", "5353", "local port to listen on") //todo: change to 853
	blocklistBool := flag.Bool("block", true, "wheter or not to use a blocklist")
	blocklistUrl := flag.String("blocklist", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "url of blocklist to use")
	injectlistBool := flag.Bool("inject", true, "wheter or not to inject a list of domains")
	injectlistFile := flag.String("injectlist", "./inject.txt", "file containing a list of domains to inject")
	flag.Parse()

	var list = make(map[string]string)
	if *blocklistBool {
		loadList(list, *blocklistUrl, true)
	}
	if *injectlistBool {
		loadList(list, *injectlistFile, false)
	}

	var c cache
	c.entries = make(map[dns.Question]cacheEntry)

	certPEMBlock, err := os.ReadFile("cert.pem")
	if err != nil {
		log.Fatal("error parsing public key, `cert.pem`", err)
	}

	keyPEMBlock, err := os.ReadFile("key.pem")
	if err != nil {
		log.Fatal("error parsing private key, `key.pem`", err)
	}

	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatal(err)
	}

	var tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}}

	local, err := tls.Listen("tcp", ":"+*localPort, tlsConf)
	if err != nil {
		log.Fatal(err)
	}

	upstreamDialer := &tls.Dialer{
		Config: tlsConf,
	}

	upstreamConn, err := upstreamDialer.Dial("tcp", *upstream)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		//clear outdated cache entries
		for {
			c.Lock()
			for i, entry := range c.entries {
				if time.Since(entry.t) > cacheValidTime {
					log.Println("deleting cache entry", entry)
					delete(c.entries, i)
				}
			}
			c.Unlock()

			time.Sleep(cacheValidTime / 2)
		}
	}()

	for {
		localConn, err := local.Accept()
		if err != nil {
			log.Println("local accept error", err)
			return
		}

		go handleConnection(localConn, upstreamConn, &c, list)
	}
}
