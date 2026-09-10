package trojan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

func TestReadConnectTargetPreservesPayload(t *testing.T) {
	credential := HashPassword(RawPassword("alice", "direct", "secret"))
	request := append([]byte(credential+"\r\n\x01\x03\x0bexample.com"), 0, 0)
	binary.BigEndian.PutUint16(request[len(request)-2:], 443)
	request = append(request, '\r', '\n')
	request = append(request, []byte("payload")...)

	reader := bytes.NewReader(request)
	gotCredential, err := ReadCredential(reader)
	if err != nil || gotCredential != credential {
		t.Fatalf("ReadCredential = (%q, %v)", gotCredential, err)
	}
	target, err := ReadConnectTarget(reader)
	if err != nil || target != "example.com:443" {
		t.Fatalf("ReadConnectTarget = (%q, %v)", target, err)
	}
	remaining := make([]byte, reader.Len())
	if _, err := reader.Read(remaining); err != nil || string(remaining) != "payload" {
		t.Fatalf("payload = %q, %v", remaining, err)
	}
}

func TestReadConnectTargetAcceptsEveryAddressType(t *testing.T) {
	longestDomain := string(bytes.Repeat([]byte{'a'}, 255))
	tests := []struct {
		name    string
		request []byte
		target  string
	}{
		{
			name:    "ipv4",
			request: []byte{0x01, addressIPv4, 198, 51, 100, 12, 0x01, 0xbb, '\r', '\n'},
			target:  "198.51.100.12:443",
		},
		{
			name:    "ipv6",
			request: append([]byte{0x01, addressIPv6, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90}, '\r', '\n'),
			target:  "[2001:db8::1]:8080",
		},
		{
			name:    "domain",
			request: append(append([]byte{0x01, addressDomain, 255}, longestDomain...), 0, 53, '\r', '\n'),
			target:  longestDomain + ":53",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target, err := ReadConnectTarget(bytes.NewReader(test.request))
			if err != nil || target != test.target {
				t.Fatalf("ReadConnectTarget = (%q, %v), want %q", target, err, test.target)
			}
		})
	}
}

func TestReadConnectTargetRejectsInvalidRequests(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "bind", data: []byte{0x02, 0x01, 127, 0, 0, 1, 0, 80, '\r', '\n'}},
		{name: "unknown command", data: []byte{0x07, 0x01, 127, 0, 0, 1, 0, 80, '\r', '\n'}},
		{name: "udp associate", data: []byte{0x03, 0x01, 127, 0, 0, 1, 0, 80, '\r', '\n'}},
		{name: "empty domain", data: []byte{0x01, 0x03, 0, 0, 80, '\r', '\n'}},
		{name: "zero port", data: []byte{0x01, 0x01, 127, 0, 0, 1, 0, 0, '\r', '\n'}},
		{name: "bad delimiter", data: []byte{0x01, 0x01, 127, 0, 0, 1, 0, 80, '\n', '\n'}},
		{name: "unknown address type", data: []byte{0x01, 0x05, 127, 0, 0, 1, 0, 80, '\r', '\n'}},
		{name: "truncated ipv6", data: []byte{0x01, addressIPv6, 0x20, 0x01, 0, 80, '\r', '\n'}},
		{name: "domain with colon", data: []byte{0x01, addressDomain, 3, 'a', ':', 'b', 0, 80, '\r', '\n'}},
		{name: "domain with NUL", data: []byte{0x01, addressDomain, 3, 'a', 0, 'b', 0, 80, '\r', '\n'}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ReadConnectTarget(bytes.NewReader(test.data)); err == nil {
				t.Fatal("invalid request was accepted")
			}
		})
	}
}

func TestReadRequestAcceptsNominalUDPAssociate(t *testing.T) {
	// Clients commonly send an unspecified address and port zero for the
	// nominal UDP ASSOCIATE header.
	header := []byte{0x03, addressIPv4, 0, 0, 0, 0, 0, 0, '\r', '\n'}
	request, err := ReadRequest(bytes.NewReader(header))
	if err != nil {
		t.Fatalf("ReadRequest = %v", err)
	}
	if !request.UDPAssociate() || request.Target != "0.0.0.0:0" {
		t.Fatalf("request = %#v", request)
	}
	if _, err := ReadConnectTarget(bytes.NewReader(header)); err == nil {
		t.Fatal("ReadConnectTarget accepted a UDP ASSOCIATE request")
	}
}

func TestUDPPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		source string
	}{
		{name: "ipv4", source: "203.0.113.7:53"},
		{name: "ipv6", source: "[2001:db8::1]:853"},
		{name: "domain", source: "resolver.example.com:5353"},
		{name: "ipv6 zone", source: "[fe80::1%eth0]:5353"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := []byte("datagram payload")
			packet, err := AppendPacket(nil, test.source, payload)
			if err != nil {
				t.Fatalf("AppendPacket = %v", err)
			}
			buffer := make([]byte, MaxUDPPayloadSize)
			target, read, err := ReadPacket(bytes.NewReader(packet), buffer)
			if err != nil {
				t.Fatalf("ReadPacket = %v", err)
			}
			if string(buffer[:read]) != string(payload) {
				t.Fatalf("payload = %q, want %q", buffer[:read], payload)
			}
			want := test.source
			if test.name == "ipv6 zone" {
				want = "[fe80::1]:5353"
			}
			if target != want {
				t.Fatalf("target = %q, want %q", target, want)
			}
		})
	}
}

func TestReadPacketConsumesOnlyOnePacket(t *testing.T) {
	first, err := AppendPacket(nil, "198.51.100.9:5000", []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	both, err := AppendPacket(first, "198.51.100.9:5001", []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	reader := bytes.NewReader(both)
	buffer := make([]byte, MaxUDPPayloadSize)
	if target, read, err := ReadPacket(reader, buffer); err != nil || target != "198.51.100.9:5000" || string(buffer[:read]) != "one" {
		t.Fatalf("first packet = (%q, %q, %v)", target, buffer[:read], err)
	}
	if target, read, err := ReadPacket(reader, buffer); err != nil || target != "198.51.100.9:5001" || string(buffer[:read]) != "two" {
		t.Fatalf("second packet = (%q, %q, %v)", target, buffer[:read], err)
	}
	if _, _, err := ReadPacket(reader, buffer); err != io.EOF {
		t.Fatalf("clean close = %v, want io.EOF", err)
	}
}

func TestReadPacketRejectsInvalidPackets(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "unknown address type", data: []byte{0x02, 127, 0, 0, 1, 0, 53, 0, 1, '\r', '\n', 'a'}},
		{name: "zero port", data: []byte{addressIPv4, 127, 0, 0, 1, 0, 0, 0, 1, '\r', '\n', 'a'}},
		{name: "bad delimiter", data: []byte{addressIPv4, 127, 0, 0, 1, 0, 53, 0, 1, '\n', '\n', 'a'}},
		{name: "truncated payload", data: []byte{addressIPv4, 127, 0, 0, 1, 0, 53, 0, 4, '\r', '\n', 'a'}},
		{name: "truncated header", data: []byte{addressIPv4, 127, 0, 0, 1, 0}},
		{name: "empty domain", data: []byte{addressDomain, 0, 0, 53, 0, 1, '\r', '\n', 'a'}},
	}
	buffer := make([]byte, MaxUDPPayloadSize)
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := ReadPacket(bytes.NewReader(test.data), buffer); err == nil {
				t.Fatal("invalid packet was accepted")
			}
		})
	}
}

func TestReadPacketRejectsPayloadBeyondBuffer(t *testing.T) {
	packet, err := AppendPacket(nil, "192.0.2.1:53", bytes.Repeat([]byte{'x'}, 2048))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadPacket(bytes.NewReader(packet), make([]byte, 1024)); !errors.Is(err, ErrInvalidPacket) {
		t.Fatalf("err = %v, want ErrInvalidPacket", err)
	}
}

func TestAppendPacketRejectsUnencodableSource(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		payload []byte
	}{
		{name: "missing port", source: "192.0.2.1", payload: []byte("x")},
		{name: "zero port", source: "192.0.2.1:0", payload: []byte("x")},
		{name: "empty host", source: ":53", payload: []byte("x")},
		{name: "oversized payload", source: "192.0.2.1:53", payload: make([]byte, MaxUDPPayloadSize+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := AppendPacket(nil, test.source, test.payload); err == nil {
				t.Fatal("unencodable packet was accepted")
			}
		})
	}
}

// FuzzReadPacket ensures no arbitrary client datagram framing can panic the
// parser or make it read past the caller's buffer.
func FuzzReadPacket(f *testing.F) {
	seed, err := AppendPacket(nil, "192.0.2.1:53", []byte("seed"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte{addressDomain, 3, 'a', 'b', 'c', 0, 53, 0, 0, '\r', '\n'})
	f.Add([]byte{addressIPv6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 53, 0, 1, '\r', '\n', 'z'})
	f.Fuzz(func(t *testing.T, data []byte) {
		buffer := make([]byte, 4096)
		target, read, err := ReadPacket(bytes.NewReader(data), buffer)
		if err != nil {
			return
		}
		if read < 0 || read > len(buffer) {
			t.Fatalf("read = %d for buffer of %d bytes", read, len(buffer))
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			t.Fatalf("target %q is not host:port: %v", target, err)
		}
	})
}

// FuzzReadRequest ensures the request header parser stays bounded for arbitrary
// input and never reports an unsupported command as accepted.
func FuzzReadRequest(f *testing.F) {
	f.Add([]byte{0x01, addressIPv4, 127, 0, 0, 1, 0, 80, '\r', '\n'})
	f.Add([]byte{0x03, addressIPv4, 0, 0, 0, 0, 0, 0, '\r', '\n'})
	f.Add([]byte{0x02, addressDomain, 1, 'a', 0, 80, '\r', '\n'})
	f.Fuzz(func(t *testing.T, data []byte) {
		request, err := ReadRequest(bytes.NewReader(data))
		if err != nil {
			return
		}
		if request.Command != commandConnect && request.Command != commandUDPAssociate {
			t.Fatalf("accepted command %#x", request.Command)
		}
		if _, _, err := net.SplitHostPort(request.Target); err != nil {
			t.Fatalf("target %q is not host:port: %v", request.Target, err)
		}
	})
}
