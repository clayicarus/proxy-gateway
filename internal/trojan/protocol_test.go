package trojan

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestParseRequestAddressTypesAndPreservesPayload(t *testing.T) {
	credential := strings.Repeat("a", credentialLength)
	tests := []struct {
		name       string
		addressTyp byte
		address    []byte
		want       string
	}{
		{name: "IPv4", addressTyp: addressIPv4, address: net.ParseIP("192.0.2.1").To4(), want: "192.0.2.1:443"},
		{name: "domain", addressTyp: addressDomain, address: append([]byte{11}, []byte("example.com")...), want: "example.com:443"},
		{name: "IPv6", addressTyp: addressIPv6, address: net.ParseIP("2001:db8::1").To16(), want: "[2001:db8::1]:443"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header := requestBytes(credential, commandConnect, test.addressTyp, test.address, 443, "\r\n", "\r\n")
			reader := bytes.NewBuffer(append(header, []byte("payload")...))
			request, err := ParseRequest(reader)
			if err != nil {
				t.Fatal(err)
			}
			if request.Credential != credential || request.Target != test.want {
				t.Fatalf("request credential or target mismatch (target=%q)", request.Target)
			}
			if got := reader.String(); got != "payload" {
				t.Fatalf("payload was consumed: %q remains", got)
			}
		})
	}
}

func TestParseRequestRejectsMalformedHeaders(t *testing.T) {
	credential := strings.Repeat("a", credentialLength)
	validDomain := append([]byte{11}, []byte("example.com")...)
	tests := []struct {
		name   string
		header []byte
		want   error
	}{
		{name: "uppercase credential", header: requestBytes(strings.Repeat("A", credentialLength), commandConnect, addressDomain, validDomain, 443, "\r\n", "\r\n"), want: ErrInvalidCredential},
		{name: "credential delimiter", header: requestBytes(credential, commandConnect, addressDomain, validDomain, 443, "\n\n", "\r\n"), want: ErrInvalidDelimiter},
		{name: "BIND", header: requestBytes(credential, 0x02, addressDomain, validDomain, 443, "\r\n", "\r\n"), want: ErrInvalidCommand},
		{name: "UDP associate", header: requestBytes(credential, 0x03, addressDomain, validDomain, 443, "\r\n", "\r\n"), want: ErrInvalidCommand},
		{name: "unknown address type", header: requestBytes(credential, commandConnect, 0x7f, nil, 443, "\r\n", "\r\n"), want: ErrInvalidAddress},
		{name: "empty domain", header: requestBytes(credential, commandConnect, addressDomain, []byte{0}, 443, "\r\n", "\r\n"), want: ErrInvalidAddress},
		{name: "domain NUL", header: requestBytes(credential, commandConnect, addressDomain, []byte{3, 'a', 0, 'b'}, 443, "\r\n", "\r\n"), want: ErrInvalidAddress},
		{name: "zero port", header: requestBytes(credential, commandConnect, addressDomain, validDomain, 0, "\r\n", "\r\n"), want: ErrInvalidPort},
		{name: "request delimiter", header: requestBytes(credential, commandConnect, addressDomain, validDomain, 443, "\r\n", "xx"), want: ErrInvalidDelimiter},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseRequest(bytes.NewReader(test.header))
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseRequestRejectsEveryTruncatedPrefix(t *testing.T) {
	credential := strings.Repeat("a", credentialLength)
	header := requestBytes(credential, commandConnect, addressIPv6, net.ParseIP("2001:db8::1").To16(), 443, "\r\n", "\r\n")
	for length := 0; length < len(header); length++ {
		if _, err := ParseRequest(bytes.NewReader(header[:length])); err == nil {
			t.Fatalf("prefix length %d was accepted", length)
		}
	}
}

func TestParseRequestDomainIsBoundedToOneByteLength(t *testing.T) {
	credential := strings.Repeat("a", credentialLength)
	domain := bytes.Repeat([]byte{'a'}, 255)
	header := requestBytes(credential, commandConnect, addressDomain, append([]byte{255}, domain...), 443, "\r\n", "\r\n")
	request, err := ParseRequest(bytes.NewReader(header))
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSuffix(request.Target, ":443")) != 255 {
		t.Fatalf("unexpected target length: %d", len(request.Target))
	}

	// A 256th byte cannot be represented by the one-byte length. It is treated
	// as part of the fixed suffix and the malformed delimiter is rejected.
	overlong := requestBytes(credential, commandConnect, addressDomain, append([]byte{255}, append(domain, 'b')...), 443, "\r\n", "\r\n")
	if _, err := ParseRequest(bytes.NewReader(overlong)); err == nil {
		t.Fatal("overlong domain encoding was accepted")
	}
}

func FuzzParseRequest(f *testing.F) {
	credential := strings.Repeat("a", credentialLength)
	f.Add(requestBytes(credential, commandConnect, addressDomain, append([]byte{11}, []byte("example.com")...), 443, "\r\n", "\r\n"))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, 1024))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ParseRequest(bytes.NewReader(data))
	})
}

func requestBytes(credential string, command, addressType byte, address []byte, port uint16, credentialDelimiter, requestDelimiter string) []byte {
	result := make([]byte, 0, len(credential)+len(address)+10)
	result = append(result, credential...)
	result = append(result, credentialDelimiter...)
	result = append(result, command, addressType)
	result = append(result, address...)
	var encodedPort [2]byte
	binary.BigEndian.PutUint16(encodedPort[:], port)
	result = append(result, encodedPort[:]...)
	result = append(result, requestDelimiter...)
	return result
}
