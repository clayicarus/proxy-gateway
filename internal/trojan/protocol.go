package trojan

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	commandConnect = 0x01
	addressIPv4    = 0x01
	addressDomain  = 0x03
	addressIPv6    = 0x04
)

var (
	ErrInvalidCredential = errors.New("invalid Trojan credential")
	ErrInvalidCommand    = errors.New("unsupported Trojan command")
	ErrInvalidAddress    = errors.New("invalid Trojan target address")
	ErrInvalidPort       = errors.New("invalid Trojan target port")
	ErrInvalidDelimiter  = errors.New("invalid Trojan delimiter")
)

// Request is a bounded, parsed Trojan TCP CONNECT request.
type Request struct {
	Credential string
	Target     string
}

// ParseRequest parses a complete Trojan request header without consuming any
// application payload that follows it.
func ParseRequest(reader io.Reader) (Request, error) {
	credential, err := ReadCredential(reader)
	if err != nil {
		return Request{}, err
	}
	target, err := ReadConnectTarget(reader)
	if err != nil {
		return Request{}, err
	}
	return Request{Credential: credential, Target: target}, nil
}

// ReadCredential reads exactly SHA224(password) followed by CRLF.
func ReadCredential(reader io.Reader) (string, error) {
	var encoded [credentialLength + 2]byte
	if _, err := io.ReadFull(reader, encoded[:]); err != nil {
		return "", fmt.Errorf("%w: truncated", ErrInvalidCredential)
	}
	if encoded[credentialLength] != '\r' || encoded[credentialLength+1] != '\n' {
		return "", ErrInvalidDelimiter
	}
	credential := string(encoded[:credentialLength])
	if !validCredential(credential) {
		return "", ErrInvalidCredential
	}
	return credential, nil
}

// ReadConnectTarget reads CONNECT + SOCKS-style address + port + CRLF.
func ReadConnectTarget(reader io.Reader) (string, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return "", fmt.Errorf("%w: truncated command", ErrInvalidCommand)
	}
	if prefix[0] != commandConnect {
		return "", ErrInvalidCommand
	}

	host, err := readHost(reader, prefix[1])
	if err != nil {
		return "", err
	}

	var suffix [4]byte
	if _, err := io.ReadFull(reader, suffix[:]); err != nil {
		return "", fmt.Errorf("%w: truncated port or delimiter", ErrInvalidAddress)
	}
	port := binary.BigEndian.Uint16(suffix[:2])
	if port == 0 {
		return "", ErrInvalidPort
	}
	if suffix[2] != '\r' || suffix[3] != '\n' {
		return "", ErrInvalidDelimiter
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func readHost(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case addressIPv4:
		var raw [net.IPv4len]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return "", fmt.Errorf("%w: truncated IPv4 address", ErrInvalidAddress)
		}
		return net.IP(raw[:]).String(), nil
	case addressIPv6:
		var raw [net.IPv6len]byte
		if _, err := io.ReadFull(reader, raw[:]); err != nil {
			return "", fmt.Errorf("%w: truncated IPv6 address", ErrInvalidAddress)
		}
		return net.IP(raw[:]).String(), nil
	case addressDomain:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return "", fmt.Errorf("%w: missing domain length", ErrInvalidAddress)
		}
		if length[0] == 0 {
			return "", fmt.Errorf("%w: empty domain", ErrInvalidAddress)
		}
		raw := make([]byte, int(length[0]))
		if _, err := io.ReadFull(reader, raw); err != nil {
			return "", fmt.Errorf("%w: truncated domain", ErrInvalidAddress)
		}
		host := string(raw)
		if strings.IndexByte(host, 0) >= 0 {
			return "", fmt.Errorf("%w: domain contains NUL", ErrInvalidAddress)
		}
		return host, nil
	default:
		return "", fmt.Errorf("%w: unknown address type", ErrInvalidAddress)
	}
}
