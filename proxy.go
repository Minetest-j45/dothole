package main

import (
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/miekg/dns"
)

var upstreamIP net.IP = net.ParseIP("208.67.220.220")
var upstreamPort string = "853"

var localPort string = "5353" //853 for tls

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

func handleConnection(localConn net.Conn, tlsConf *tls.Config) {
	upstreamDialer := &tls.Dialer{
		Config: tlsConf,
	}

	upstreamConn, err := upstreamDialer.Dial("tcp", upstreamIP.String()+":"+upstreamPort)
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
			log.Println(m.Question[0])

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
		log.Println(m.Question[0])
		log.Println(m.Answer[0])

		_, err = localConn.Write(raw)
		if err != nil {
			return
		}
	}
}

func main() {
	certPEMBlock, err := os.ReadFile("cert.pem")
	keyPEMBlock, err := os.ReadFile("key.pem")
	cert, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatal(err)
	}

	var tlsConf = &tls.Config{Certificates: []tls.Certificate{cert}}

	local, err := tls.Listen("tcp", ":"+localPort, tlsConf)
	if err != nil {
		log.Fatal(err)
	}

	for {
		localConn, err := local.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handleConnection(localConn, tlsConf)
	}
}
