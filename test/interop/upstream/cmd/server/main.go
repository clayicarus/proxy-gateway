package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"

	hyServer "github.com/apernet/hysteria/core/v2/server"
)

type authenticator struct{}

func (*authenticator) Authenticate(net.Addr, string, uint64) (bool, string) { return true, "upstream" }

func main() {
	if len(os.Args) != 3 {
		panic("usage: server cert key")
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		panic(err)
	}
	server, err := hyServer.NewServer(&hyServer.Config{
		TLSConfig: hyServer.TLSConfig{Certificates: []tls.Certificate{cert}},
		Conn:      conn, Authenticator: &authenticator{},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(conn.LocalAddr().String())
	if err := server.Serve(); err != nil {
		panic(err)
	}
}
