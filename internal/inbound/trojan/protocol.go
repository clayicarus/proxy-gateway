// Package trojan implements the bounded Trojan inbound protocol boundary for
// TCP CONNECT and UDP ASSOCIATE.
package trojan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const credentialLength = sha256.Size224 * 2

const (
	commandConnect      = 0x01
	commandUDPAssociate = 0x03
	addressIPv4         = 0x01
	addressDomain       = 0x03
	addressIPv6         = 0x04
)

// MaxUDPPayloadSize is the largest datagram the Trojan length prefix can
// describe. It is also the per-association read buffer bound.
const MaxUDPPayloadSize = 65535

// maxPacketHeaderSize bounds ATYP, the longest address, port, length and CRLF.
const maxPacketHeaderSize = 1 + 1 + 255 + 2 + 2 + 2

var (
	ErrInvalidCredential = errors.New("invalid Trojan credential")
	ErrInvalidCommand    = errors.New("unsupported Trojan command")
	ErrInvalidAddress    = errors.New("invalid Trojan target address")
	ErrInvalidPort       = errors.New("invalid Trojan target port")
	ErrInvalidDelimiter  = errors.New("invalid Trojan delimiter")
	ErrInvalidPacket     = errors.New("invalid Trojan UDP packet")
)

// RawPassword is the per-user, per-node password that a Trojan client uses.
func RawPassword(username, node, password string) string {
	return username + ":" + node + ":" + password
}

// HashPassword returns the lower-case SHA-224 value transmitted by Trojan.
func HashPassword(password string) string {
	sum := sha256.Sum224([]byte(password))
	return hex.EncodeToString(sum[:])
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

// Request is a parsed Trojan request header.
type Request struct {
	// Command is CONNECT or UDP ASSOCIATE. No other command is accepted.
	Command byte
	// Target is the requested destination for CONNECT. For UDP ASSOCIATE it is
	// only the nominal address of the request header: every datagram carries
	// its own destination, so this value must not be used to route packets.
	Target string
}

// UDPAssociate reports whether the client asked for a UDP association.
func (r Request) UDPAssociate() bool { return r.Command == commandUDPAssociate }

// ReadRequest reads the Trojan request command, its SOCKS-style address and the
// trailing CRLF. BIND and every unknown command are rejected.
func ReadRequest(reader io.Reader) (Request, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return Request{}, fmt.Errorf("%w: truncated command", ErrInvalidCommand)
	}
	if prefix[0] != commandConnect && prefix[0] != commandUDPAssociate {
		return Request{}, ErrInvalidCommand
	}
	host, err := readHost(reader, prefix[1])
	if err != nil {
		return Request{}, err
	}
	var suffix [4]byte
	if _, err := io.ReadFull(reader, suffix[:]); err != nil {
		return Request{}, fmt.Errorf("%w: truncated port or delimiter", ErrInvalidAddress)
	}
	port := binary.BigEndian.Uint16(suffix[:2])
	// The UDP ASSOCIATE header address is nominal and clients commonly send an
	// unspecified address with port zero. CONNECT must name a real port.
	if port == 0 && prefix[0] == commandConnect {
		return Request{}, ErrInvalidPort
	}
	if suffix[2] != '\r' || suffix[3] != '\n' {
		return Request{}, ErrInvalidDelimiter
	}
	return Request{Command: prefix[0], Target: net.JoinHostPort(host, strconv.Itoa(int(port)))}, nil
}

// ReadConnectTarget reads CONNECT plus its SOCKS-style address and CRLF.
func ReadConnectTarget(reader io.Reader) (string, error) {
	request, err := ReadRequest(reader)
	if err != nil {
		return "", err
	}
	if request.Command != commandConnect {
		return "", ErrInvalidCommand
	}
	return request.Target, nil
}

// ReadPacket reads one Trojan UDP packet into buffer and returns its
// destination and payload length. A clean association close is reported as
// io.EOF before any part of a packet has been consumed.
func ReadPacket(reader io.Reader, buffer []byte) (string, int, error) {
	var addressType [1]byte
	if _, err := io.ReadFull(reader, addressType[:]); err != nil {
		return "", 0, err
	}
	host, err := readHost(reader, addressType[0])
	if err != nil {
		return "", 0, err
	}
	var header [6]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return "", 0, fmt.Errorf("%w: truncated packet header", ErrInvalidPacket)
	}
	port := binary.BigEndian.Uint16(header[:2])
	if port == 0 {
		return "", 0, ErrInvalidPort
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if header[4] != '\r' || header[5] != '\n' {
		return "", 0, ErrInvalidDelimiter
	}
	if length > len(buffer) {
		return "", 0, fmt.Errorf("%w: payload of %d bytes exceeds the %d byte bound", ErrInvalidPacket, length, len(buffer))
	}
	if _, err := io.ReadFull(reader, buffer[:length]); err != nil {
		return "", 0, fmt.Errorf("%w: truncated payload", ErrInvalidPacket)
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), length, nil
}

// AppendPacket appends one Trojan UDP packet describing source to dst.
func AppendPacket(dst []byte, source string, payload []byte) ([]byte, error) {
	host, portText, err := net.SplitHostPort(source)
	if err != nil {
		return dst, fmt.Errorf("%w: %v", ErrInvalidAddress, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return dst, ErrInvalidPort
	}
	if len(payload) > MaxUDPPayloadSize {
		return dst, fmt.Errorf("%w: payload of %d bytes exceeds the %d byte bound", ErrInvalidPacket, len(payload), MaxUDPPayloadSize)
	}
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			dst = append(dst, addressIPv4)
			dst = append(dst, v4...)
		} else {
			dst = append(dst, addressIPv6)
			dst = append(dst, ip.To16()...)
		}
	} else {
		if host == "" || len(host) > 255 || strings.IndexByte(host, 0) >= 0 {
			return dst, fmt.Errorf("%w: unencodable host", ErrInvalidAddress)
		}
		dst = append(dst, addressDomain, byte(len(host)))
		dst = append(dst, host...)
	}
	var trailer [6]byte
	binary.BigEndian.PutUint16(trailer[:2], uint16(port))
	binary.BigEndian.PutUint16(trailer[2:4], uint16(len(payload)))
	trailer[4], trailer[5] = '\r', '\n'
	dst = append(dst, trailer[:]...)
	return append(dst, payload...), nil
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
		if !validDomain(host) {
			return "", fmt.Errorf("%w: domain contains a forbidden character", ErrInvalidAddress)
		}
		return host, nil
	default:
		return "", fmt.Errorf("%w: unknown address type", ErrInvalidAddress)
	}
}

// validDomain rejects control characters and every byte that would make the
// parsed target ambiguous once it is joined with its port. Non-ASCII bytes stay
// allowed so a client may send a raw internationalized hostname.
func validDomain(host string) bool {
	if host == "" {
		return false
	}
	for i := 0; i < len(host); i++ {
		switch character := host[i]; {
		case character <= ' ', character == 0x7f:
			return false
		case character == ':', character == '[', character == ']',
			character == '/', character == '\\', character == '?',
			character == '#', character == '@', character == '%':
			return false
		}
	}
	return true
}

func validCredential(credential string) bool {
	if len(credential) != credentialLength {
		return false
	}
	for i := range credential {
		if (credential[i] < '0' || credential[i] > '9') && (credential[i] < 'a' || credential[i] > 'f') {
			return false
		}
	}
	return true
}
