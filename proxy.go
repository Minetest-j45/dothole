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

var localPort int = 5353 //853 for tls

func handleConnection(localConn net.Conn, tlsConf *tls.Config) {
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

	var tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}}

	local, err := tls.Listen("tcp", ":"+fmt.Sprint(localPort), tlsConf)
	if err != nil {
		panic(err)
	}

	for {
		localConn, err := local.Accept()
		if err != nil {
			panic(err)
		}
		go handleConnection(localConn, tlsConf)
	}
}
