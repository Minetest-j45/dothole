package main

import (
	"fmt"
	"net"
)

var upstreamIP net.IP = net.ParseIP("208.67.220.220")
var upstreamPort int = 53 //853 for tls

func handleConnection(localConn net.Conn, upstream *net.TCPAddr) {
	upstreamConn, err := net.DialTCP("tcp", nil, upstream)
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
			fmt.Println(buf[:n])
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
		fmt.Println(buf[:n])
		_, err = localConn.Write(buf[:n])
		if err != nil {
			return
		}
	}
}

func main() {
	upstream := &net.TCPAddr{IP: upstreamIP, Port: upstreamPort}
	local, err := net.Listen("tcp", ":53")
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
