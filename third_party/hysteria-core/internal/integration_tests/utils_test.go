package integration_tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

// This file provides utilities for the integration tests.

func serverTLSConfig() server.TLSConfig {
	// Generate a short-lived certificate so clean checkouts need no fixture files.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	return server.TLSConfig{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
}

func serverConn() (net.PacketConn, net.Addr, error) {
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 14514}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, nil, err
	}
	return udpConn, udpAddr, nil
}

// tcpEchoServer is a TCP server that echoes what it reads from the connection.
// It will never actively close the connection.
type tcpEchoServer struct {
	Listener net.Listener
}

func (s *tcpEchoServer) Serve() error {
	for {
		conn, err := s.Listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			_, _ = io.Copy(conn, conn)
			_ = conn.Close()
		}()
	}
}

func (s *tcpEchoServer) Close() error {
	return s.Listener.Close()
}

// udpEchoServer is a UDP server that echoes what it reads from the connection.
// It will never actively close the connection.
type udpEchoServer struct {
	Conn net.PacketConn
}

func (s *udpEchoServer) Serve() error {
	buf := make([]byte, 65536)
	for {
		n, addr, err := s.Conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		_, err = s.Conn.WriteTo(buf[:n], addr)
		if err != nil {
			return err
		}
	}
}

func (s *udpEchoServer) Close() error {
	return s.Conn.Close()
}
