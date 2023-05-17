package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	//"github.com/prometheus/client_golang/prometheus/promauto"
)

var client *dns.Client
var c cache
var list map[string]string
var clientConn *dns.Conn
var upstreamAddr *string

var prometheusBool *bool
var prometheusStats = make(map[string]prometheus.Counter)

type cacheEntry struct {
	compress bool
	question dns.Question
	answer   []dns.RR
	ra       bool
	t        time.Time
}

type cache struct {
	sync.RWMutex
	entries map[dns.Question]cacheEntry
}

const cacheValidTime time.Duration = 300 * time.Second

func loadList(list map[string]string, location string) {
	var scanner *bufio.Scanner
	if strings.HasPrefix(location, "http://") || strings.HasPrefix(location, "https://") {
		resp, err := http.Get(location)
		if err != nil {
			log.Println("error getting list", location, err)
			return
		}
		defer resp.Body.Close()

		scanner = bufio.NewScanner(resp.Body)
	} else {
		f, err := os.Open(location)
		if err != nil {
			log.Println("error opening file", err)
		}
		defer f.Close()

		scanner = bufio.NewScanner(f)
	}

	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if strings.HasPrefix(scanner.Text(), "#") || len(parts) != 2 {
			continue
		}

		list[parts[1]+"."] = parts[0] // add to list
	}
}

var (
	upstreamNet        = flag.String("un", "tcp-tls", "Type of upstream network connection to use (udp, tcp, tcp-tls)")
	upstreamAddr       = flag.String("ua", "208.67.220.220:853", "Upstream DNS server address to use (ipaddr:port)")
	localNet           = flag.String("ln", "tcp-tls", "Type of local network connection to use (udp, tcp, tcp-tls)")
	localPort          = flag.String("lp", "853", "Local port to listen on")
	blocklistBool      = flag.Bool("be", true, "Whether to use a blocklist")
	blocklistLocation  = flag.String("bl", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "URL or file containing a list of domains to block")
	injectlistBool     = flag.Bool("ie", true, "Whether or not to inject a list of domains")
	injectlistLocation = flag.String("il", "./inject.txt", "URL or file containing a list of domains to inject")
	prometheusBool     = flag.Bool("pb", true, "Whether to run a prometheus client and http server")
	//prometheusHttpsPort = flag.String("pp", "8080", "The port for the prometheus http server to serve on")
)

func main() {
	flag.Parse()

    if *prometheusBool {
        go startPrometheus(prometheusStats)
    }

	switch *upstreamNet {
	case "udp", "tcp", "tcp-tls":
	default:
		log.Fatal("upstream-net needs to be either udp, tcp, or tcp-tls")
	}

	switch *localNet {
	case "udp", "tcp", "tcp-tls":
	default:
		log.Fatal("local-net needs to be either udp, tcp, or tcp-tls")
	}

	list = make(map[string]string)
	wg := sync.WaitGroup{}
	if *blocklistBool {
		wg.Add(1)
		go func() {
			loadList(list, *blocklistLocation)
			wg.Done()
		}()
	}
	if *injectlistBool {
		wg.Add(1)
		go func() {
			loadList(list, *injectlistLocation)
			wg.Done()
		}()
	}

	wg.Wait()

	c.entries = make(map[dns.Question]cacheEntry)

	go func() { //clear outdated cache entries
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

	cert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
	if err != nil {
		log.Fatal(err)
	}

	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}}

	dns.HandleFunc(".", handleRequest)
	client = &dns.Client{Net: *upstreamNet, TLSConfig: tlsConf}
	clientConn, err = client.Dial(*upstreamAddr)
	if err != nil {
		log.Fatal("error connecting to upstream server:", err)
	}

	server := &dns.Server{Addr: ":" + *localPort, Net: *localNet, TLSConfig: tlsConf}
	defer server.Shutdown()
	log.Println("ready")
	err = server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func handleRequest(w dns.ResponseWriter, request *dns.Msg) {
    go func() {
        if *prometheusBool {
            prometheusStats["total_queries"].Inc()
        }
    }()

	request.Question[0].Name = strings.ToLower(request.Question[0].Name)

    c.RLock()
    entry, ok := c.entries[request.Question[0]]
    c.RUnlock()

    if ok && time.Since(entry.t) < cacheValidTime { //check if cache entry is still valid
        log.Println("replying to", request.Question[0], "with cache:", entry)
        reply := new(dns.Msg)
        reply.SetReply(request)
        reply.Compress = entry.compress
        reply.Answer = entry.answer
        reply.MsgHdr.RecursionAvailable = entry.ra
        w.WriteMsg(reply)
        return
    }

    if list != nil && request.Question[0].Qtype == dns.TypeA {
        if block, ok := list[request.Question[0].Name]; ok { //check blocklist for the question
            log.Println("blocked/injected:", request.Question[0].Name, "to:", block)
            reply := new(dns.Msg)
            reply.SetReply(request)
            reply.Answer = append(reply.Answer, &dns.A{
                Hdr: dns.RR_Header{
                    Name:   request.Question[0].Name,
                    Rrtype: dns.TypeA,
                    Class:  dns.ClassINET,
                    Ttl:    0,
                },
                A: net.ParseIP(block),
            })
            reply.MsgHdr.RecursionAvailable = true
            w.WriteMsg(reply)
            return
        }
    }


RETRY:
	reply, _, err := client.ExchangeWithConn(request, clientConn)
	if err != nil {
		switch {
		case
			errors.Is(err, net.ErrClosed),
			errors.Is(err, io.EOF),
			errors.Is(err, syscall.EPIPE):
			log.Println("reopenning connection after closed:", err)
			clientConn, err = client.Dial(*upstreamAddr)
			if err != nil {
				log.Fatal("error reconnecting to upstream server:", err)
			}
			goto RETRY
		default:
			log.Println("unable to process error:", err)
		}
		return
	}

	c.Lock()
	c.entries[reply.Question[0]] = cacheEntry{reply.Compress, reply.Question[0], reply.Answer /*recursive answers possible (e.g. with CNAME records)*/, reply.RecursionAvailable, time.Now()}
	c.Unlock()

    w.WriteMsg(reply)
}
