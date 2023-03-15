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
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

var upstream *string
var localPort *string

type cacheEntry struct {
	q dns.Question
	a dns.RR
	t time.Time
}

type cache struct {
	sync.RWMutex
	entries []cacheEntry
}

var cacheValidTime time.Duration = 10 * time.Second //todo: change to around 300 seconds

func readPacket(conn net.Conn) ([]byte, []byte, error) {
	buf := make([]byte, 2)
	_, err := conn.Read(buf)
	if err != nil {
		return nil, nil, errors.New("failed to read packet length")
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
		return nil, nil, errors.New("failed to read packet")
	}

	copy(raw[2:], buf)

	return raw, buf, nil
}

func handleConnection(localConn net.Conn, tlsConf *tls.Config, c *cache) {
	upstreamDialer := &tls.Dialer{
		Config: tlsConf,
	}

	upstreamConn, err := upstreamDialer.Dial("tcp", *upstream)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			raw, n, err := readPacket(localConn)
			if err != nil {
				return
			}

			m := new(dns.Msg)
			err = m.Unpack(n)
			if err != nil {
				log.Fatal(err)
			}

			//check cache for the question
			c.Lock()
			for i, entry := range c.entries {
				if entry.q == m.Question[0] {

					//check if cache entry is still valid
					if time.Since(entry.t) < cacheValidTime {

						response := new(dns.Msg)
						response.SetReply(m)
						response.Answer = append(response.Answer, entry.a)

						responseRaw, err := response.Pack()
						if err != nil {
							return
						}

						//add 2 bytes length to the beginning of the packet
						responseRaw = append([]byte{byte(len(responseRaw) >> 8), byte(len(responseRaw))}, responseRaw...)

						_, err = localConn.Write(responseRaw)
						if err != nil {
							return
						}

						break
					} else {
						//delete entry if it is not valid anymore
						c.entries = append((c.entries)[:i], (c.entries)[i+1:]...)

					}
				}
			}
			c.Unlock()

			_, err = upstreamConn.Write(raw)
			if err != nil {
				return
			}
		}
	}()

	for {
		raw, n, err := readPacket(upstreamConn)
		if err != nil {
			return
		}

		m := new(dns.Msg)
		err = m.Unpack(n)
		if err != nil {
			log.Fatal(err)
		}

		if len(m.Answer) != 0 {
			c.Lock()
			for i, entry := range c.entries {
				if entry.q == m.Question[0] {
					c.entries = append((c.entries)[:i], (c.entries)[i+1:]...) //delete entry if it already exists
					log.Println("replacing old entry from cache:", entry.q.Name)
				}
			}

			//add to cache
			c.entries = append(c.entries, cacheEntry{m.Question[0], m.Answer[0], time.Now()})
			c.Unlock()
		}

		_, err = localConn.Write(raw)
		if err != nil {
			return
		}
	}
}

func main() {
	upstream = flag.String("upstream", "208.67.220.220:853", "upstream DNS over TLS server to use, format is ipaddr:port")
	localPort = flag.String("local", "5353", "local port to listen on") //todo: change to 853
	flag.Parse()

	blocklist := loadList()
	var c cache

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

	go func() {
		//clear outdated cache entries
		for {
			c.Lock()
			for i, entry := range c.entries {
				if time.Since(entry.t) > cacheValidTime {
					log.Println("deleting cache entry", entry)
					c.entries = append(c.entries[:i], c.entries[i+1:]...)
				}
			}
			c.Unlock()

			time.Sleep(cacheValidTime / 2)
		}
	}()

	for {
		localConn, err := local.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(localConn, tlsConf, &c)
	}
}
