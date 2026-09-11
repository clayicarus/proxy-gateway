package main

import (
	"fmt"
	"io"
	"net"
	"os"

	hyClient "github.com/apernet/hysteria/core/v2/client"
)

func main() {
	if len(os.Args) != 4 {
		panic("usage: client server target auth")
	}
	serverAddr, err := net.ResolveUDPAddr("udp", os.Args[1])
	if err != nil {
		panic(err)
	}
	client, _, err := hyClient.NewClient(&hyClient.Config{
		ServerAddr: serverAddr, Auth: os.Args[3],
		TLSConfig: hyClient.TLSConfig{ServerName: "localhost", InsecureSkipVerify: true},
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()
	conn, err := client.TCP(os.Args[2])
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	payload := []byte("upstream-client")
	if _, err := conn.Write(payload); err != nil {
		panic(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		panic(err)
	}
	if string(got) != string(payload) {
		panic(fmt.Sprintf("echo mismatch: %q", got))
	}
}
