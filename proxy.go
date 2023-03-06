package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
)

var upstreamIP net.IP = net.ParseIP("208.67.220.220")
var upstreamPort int = 853
var localPort int = 5353

//var upstreamPort int = 53 //853 for tls

func handleConnection(localConn net.Conn, upstream *net.TCPAddr) {
	certPEMBlock, err := ioutil.ReadFile("cert.pem")
	keyPEMBlock, err := ioutil.ReadFile("key.pem")
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)

	if err != nil {
		panic(err)
	}

	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS13,
		ClientAuth:         tls.RequireAndVerifyClientCert,
	}

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
			fmt.Println(string(buf[:n]))
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
		fmt.Println(string(buf[:n]))
		_, err = localConn.Write(buf[:n])
		if err != nil {
			return
		}
	}
}

func main() {
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
