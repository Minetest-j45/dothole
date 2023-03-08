package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"strings"

	"github.com/miekg/dns"
)

var upstreamIP net.IP = net.ParseIP("208.67.220.220")
var upstreamPort int = 853
var localPort int = 5353

var tlsConf = &tls.Config{
	InsecureSkipVerify: true,
	MinVersion:         tls.VersionTLS13,
	ClientAuth:         tls.RequireAndVerifyClientCert,
}

func handleConnection(localConn net.Conn, upstream *net.TCPAddr) {
	upstreamDialer := &tls.Dialer{
		Config: tlsConf,
	}

	upstreamConn, err := upstreamDialer.Dial("tcp", upstreamIP.String()+":"+fmt.Sprint(upstreamPort))
	if err != nil {
		panic(err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}

			name, _, _ := dns.UnpackDomainName(buf[:n], 14)
			fmt.Println(strings.TrimRight(name, "."))

			_, err = upstreamConn.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 4096)
	for {
		n, err := upstreamConn.Read(buf)
		if err != nil {
			return
		}
		//fmt.Println(buf[:n])
		_, err = localConn.Write(buf[:n])
		if err != nil {
			return
		}
	}
}

func main() {
	certPEMBlock, err := ioutil.ReadFile("cert.pem")
	keyPEMBlock, err := ioutil.ReadFile("key.pem")
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		panic(err)
	}
	tlsConf.Certificates = []tls.Certificate{cert}

	upstream := &net.TCPAddr{IP: upstreamIP, Port: upstreamPort}

	local, err := net.Listen("tcp", ":"+fmt.Sprint(localPort))
	if err != nil {
		panic(err)
	}

	for {
		localConn, err := local.Accept()
		if err != nil {
			panic(err)
		}
		go handleConnection(localConn, upstream)
	}
}
