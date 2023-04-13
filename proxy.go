package main

import (
	"crypto/tls"
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

var upstreamAddr string
var client *dns.Client
var c cache
var list map[string]string

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

		list[parts[1]+"."] = parts[0] // add to list
	}
}

func main() {
	upstreamAddr = *flag.String("upstream", "208.67.220.220:853", "upstream DNS over TLS server to use, format is ipaddr:port")
	localPort := flag.String("local", "5353", "local port to listen on") //todo: change to 853
	blocklistBool := flag.Bool("block", true, "wheter or not to use a blocklist")
	blocklistUrl := flag.String("blocklist", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", "url of blocklist to use")
	injectlistBool := flag.Bool("inject", true, "wheter or not to inject a list of domains")
	injectlistFile := flag.String("injectlist", "./inject.txt", "file containing a list of domains to inject")
	flag.Parse()

	list = make(map[string]string)
	if *blocklistBool {
		loadList(list, *blocklistUrl, true)
	}
	if *injectlistBool {
		loadList(list, *injectlistFile, false)
	}

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

	tlsConf := &tls.Config{Certificates: []tls.Certificate{cert}}

	dns.HandleFunc(".", handleRequest)

	client = &dns.Client{Net: "tcp-tls", TLSConfig: tlsConf}
	server := &dns.Server{Addr: ":" + *localPort, Net: "tcp-tls", TLSConfig: tlsConf}
	err = server.ListenAndServe()
	defer server.Shutdown()
	if err != nil {
		fmt.Println(err)
	}
}

func handleRequest(w dns.ResponseWriter, request *dns.Msg) {
	c.RLock()
	entry, ok := c.entries[request.Question[0]]
	c.RUnlock()

	if ok {
		if time.Since(entry.t) < cacheValidTime { //check if cache entry is still valid
			fmt.Println("replying to", request.Question[0], "with cache:", entry)
			reply := new(dns.Msg)
			reply.SetReply(request)
			reply.Compress = entry.compress
			reply.Answer = entry.answer
			reply.MsgHdr.RecursionAvailable = entry.ra
			w.WriteMsg(reply)
			return
		} else {
			c.Lock()
			delete(c.entries, entry.question) //delete entry if it is not valid anymore
			c.Unlock()
		}
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

	reply, _, err := client.Exchange(request, upstreamAddr)
	if err != nil {
		return
	}

	c.Lock()
	c.entries[reply.Question[0]] = cacheEntry{reply.Compress, reply.Question[0], reply.Answer /*recursive answers possible (e.g. with CNAME records)*/, reply.RecursionAvailable, time.Now()}
	c.Unlock()

	w.WriteMsg(reply)
}
