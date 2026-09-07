package server

import (
	"errors"
	"sync"
	"testing"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

type gatewayTestUDPIO struct {
	manager *udpSessionManager
	mu      sync.Mutex
	admit   []RequestInfo
	charges []uint64
	conn    *gatewayTestUDPConn
}

func (i *gatewayTestUDPIO) ReceiveMessage() (*protocol.UDPMessage, error) {
	return nil, errors.New("closed")
}
func (i *gatewayTestUDPIO) SendMessage([]byte, *protocol.UDPMessage) error { return nil }
func (i *gatewayTestUDPIO) Hook([]byte, *string) error                     { return nil }
func (i *gatewayTestUDPIO) UDP(string) (UDPConn, error)                    { return i.conn, nil }
func (i *gatewayTestUDPIO) Admit(request RequestInfo, _ *protocol.UDPMessage, tx, _ uint64) bool {
	if i.manager.Count() != 1 {
		panic("association was not published before accounting")
	}
	i.mu.Lock()
	i.admit = append(i.admit, request)
	i.charges = append(i.charges, tx)
	i.mu.Unlock()
	return true
}
func (i *gatewayTestUDPIO) SendMessageContext(request RequestInfo, _ []byte, msg *protocol.UDPMessage) error {
	i.mu.Lock()
	i.admit = append(i.admit, request)
	i.charges = append(i.charges, uint64(len(msg.Data)))
	first := len(i.charges) == 1
	i.mu.Unlock()
	if first {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: 1200}
	}
	return nil
}
func (i *gatewayTestUDPIO) UDPContext(RequestInfo) (UDPConn, error) { return i.conn, nil }

type gatewayTestUDPConn struct {
	once   sync.Once
	closed chan struct{}
}

func newGatewayTestUDPConn() *gatewayTestUDPConn {
	return &gatewayTestUDPConn{closed: make(chan struct{})}
}
func (c *gatewayTestUDPConn) ReadFrom([]byte) (int, string, error) {
	<-c.closed
	return 0, "", errors.New("closed")
}
func (c *gatewayTestUDPConn) WriteTo(data []byte, _ string) (int, error) { return len(data), nil }
func (c *gatewayTestUDPConn) Close() error                               { c.once.Do(func() { close(c.closed) }); return nil }

type gatewayTestEvents struct {
	newRequests []RequestInfo
	closed      []RequestInfo
}

func (e *gatewayTestEvents) New(uint32, string)                  {}
func (e *gatewayTestEvents) Close(uint32, error)                 {}
func (e *gatewayTestEvents) NewSession(r RequestInfo)            { e.newRequests = append(e.newRequests, r) }
func (e *gatewayTestEvents) CloseSession(r RequestInfo, _ error) { e.closed = append(e.closed, r) }

func TestGatewayUDPFirstFragmentCreatesIdentityBeforeAccounting(t *testing.T) {
	io := &gatewayTestUDPIO{conn: newGatewayTestUDPConn()}
	events := &gatewayTestEvents{}
	sm := newUDPSessionManager(io, events, defaultUDPIdleTimeout, func() uint64 { return 42 })
	io.manager = sm
	first := &protocol.UDPMessage{SessionID: 7, PacketID: 1, FragID: 0, FragCount: 2, Addr: "example.com:53", Data: []byte("abc")}
	second := &protocol.UDPMessage{SessionID: 7, PacketID: 1, FragID: 1, FragCount: 2, Addr: "example.com:53", Data: []byte("def")}
	if err := sm.feed(first); err != nil {
		t.Fatal(err)
	}
	if len(io.admit) != 1 || io.admit[0].ID != 42 || io.admit[0].AssociationID != 7 || io.admit[0].Target != first.Addr {
		t.Fatalf("first-fragment identity = %#v", io.admit)
	}
	if len(events.newRequests) != 0 {
		t.Fatal("incomplete fragment opened outbound")
	}
	if err := sm.feed(second); err != nil {
		t.Fatal(err)
	}
	if len(io.charges) != 2 || io.charges[0] != 3 || io.charges[1] != 3 {
		t.Fatalf("inbound charges = %#v", io.charges)
	}
	if len(events.newRequests) != 1 || events.newRequests[0].ID != 42 {
		t.Fatalf("events = %#v", events.newRequests)
	}
	sm.cleanup(false)
	sm.workers.Wait()
}

func TestGatewayUDPWholeAttemptAndFragmentRetriesAreAllCharged(t *testing.T) {
	io := &gatewayTestUDPIO{}
	request := RequestInfo{ID: 9, Network: "udp", Target: "example.com:53", AssociationID: 7}
	data := make([]byte, 3000)
	msg := &protocol.UDPMessage{SessionID: 7, FragCount: 1, Addr: request.Target, Data: data}
	if err := sendMessageAutoFrag(io, request, make([]byte, protocol.MaxUDPSize), msg); err != nil {
		t.Fatal(err)
	}
	var total uint64
	for _, charge := range io.charges {
		total += charge
	}
	if len(io.charges) < 3 || total != 6000 {
		t.Fatalf("charges = %#v, total=%d; want whole attempt plus fragment retries", io.charges, total)
	}
	for _, got := range io.admit {
		if got.ID != request.ID || got.AssociationID != request.AssociationID {
			t.Fatalf("request identity changed: %#v", got)
		}
	}
}
