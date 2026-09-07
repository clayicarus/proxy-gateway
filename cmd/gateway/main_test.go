package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRunGatewayContextReleasesEarlierInboundOnBindFailure(t *testing.T) {
	first := reserveUDPAddress(t)
	blocked, err := net.ListenUDP("udp", mustUDPAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Close()

	configPath := writeGatewayConfig(t, []gatewayTestInbound{
		{name: "first", listen: first},
		{name: "blocked", listen: blocked.LocalAddr().String()},
	})
	err = runGatewayContext(context.Background(), []string{"-c", configPath})
	if err == nil || !strings.Contains(err.Error(), "inbound blocked listen") {
		t.Fatalf("runGatewayContext error = %v, want blocked inbound error", err)
	}

	probe, err := net.ListenUDP("udp", mustResolveUDPAddress(t, first))
	if err != nil {
		t.Fatalf("first inbound remained bound after later bind failure: %v", err)
	}
	_ = probe.Close()
}

func TestRunGatewayContextStartsAndStopsInbound(t *testing.T) {
	address := reserveUDPAddress(t)
	configPath := writeGatewayConfig(t, []gatewayTestInbound{{name: "public", listen: address}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- runGatewayContext(ctx, []string{"-c", configPath}) }()

	waitForUDPAddressInUse(t, address)
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("runGatewayContext shutdown error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Gateway did not stop within the worker shutdown budget")
	}
}

type gatewayTestInbound struct {
	name   string
	listen string
}

func writeGatewayConfig(t *testing.T, inbounds []gatewayTestInbound) string {
	t.Helper()
	certPath, keyPath := writeGatewayTestCertificate(t)
	var builder strings.Builder
	builder.WriteString("inbounds:\n")
	for _, inbound := range inbounds {
		fmt.Fprintf(&builder, "  - name: %s\n    type: hysteria2\n    listen: %q\n", inbound.name, inbound.listen)
	}
	fmt.Fprintf(&builder, "tls:\n  cert: %q\n  key: %q\ndbPath: %q\ntimezone: UTC\n", certPath, keyPath, t.TempDir()+"/gateway.db")
	path := t.TempDir() + "/gateway.yaml"
	if err := os.WriteFile(path, []byte(builder.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeGatewayTestCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := dir+"/cert.pem", dir+"/key.pem"
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func reserveUDPAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenUDP("udp", mustUDPAddress(t))
	if err != nil {
		t.Fatal(err)
	}
	address := listener.LocalAddr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func mustUDPAddress(t *testing.T) *net.UDPAddr {
	t.Helper()
	return mustResolveUDPAddress(t, "127.0.0.1:0")
}

func mustResolveUDPAddress(t *testing.T, address string) *net.UDPAddr {
	t.Helper()
	resolved, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

func waitForUDPAddressInUse(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		probe, err := net.ListenUDP("udp", mustResolveUDPAddress(t, address))
		if err != nil {
			return
		}
		_ = probe.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("Gateway did not bind %s", address)
}
