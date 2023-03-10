package main

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"net"

	"github.com/miekg/dns"
)

var upstreamIP net.IP = net.ParseIP("208.67.220.220")
var upstreamPort string = "853"

var localPort string = "5353" //853 for tls

func handleConnection(localConn net.Conn, tlsConf *tls.Config) {
	upstreamDialer := &tls.Dialer{
		Config: tlsConf,
	}

	upstreamConn, err := upstreamDialer.Dial("tcp", upstreamIP.String()+":"+upstreamPort)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				return
			}

			name, _, err := dns.UnpackDomainName(buf[:n], 14)
			if err != nil {
				log.Fatal(err, name, buf[:n])
			}
			log.Println(name)

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

	local, err := tls.Listen("tcp", ":"+localPort, tlsConf)
	if err != nil {
		log.Fatal(err)
	}

	for {
		localConn, err := local.Accept()
		if err != nil {
			panic(err)
		}
		go handleConnection(localConn, tlsConf)
	}
}
