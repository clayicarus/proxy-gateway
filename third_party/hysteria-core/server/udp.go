package server

import (
	"errors"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/frag"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
)

const (
	idleCleanupInterval = 1 * time.Second
)

type udpIO interface {
	ReceiveMessage() (*protocol.UDPMessage, error)
	SendMessage([]byte, *protocol.UDPMessage) error
	Hook(data []byte, reqAddr *string) error
	UDP(reqAddr string) (UDPConn, error)
}

type sessionUDPIO interface {
	Admit(request RequestInfo, msg *protocol.UDPMessage, tx, rx uint64) bool
	SendMessageContext(request RequestInfo, buf []byte, msg *protocol.UDPMessage) error
	UDPContext(request RequestInfo) (UDPConn, error)
}

type udpEventLogger interface {
	New(sessionID uint32, reqAddr string)
	Close(sessionID uint32, err error)
}

type sessionUDPEventLogger interface {
	NewSession(request RequestInfo)
	CloseSession(request RequestInfo, err error)
}

type udpSessionEntry struct {
	ID           uint32
	Request      RequestInfo
	OverrideAddr string // Ignore the address in the UDP message, always use this if not empty
	OriginalAddr string // The original address in the UDP message
	D            *frag.Defragger
	Last         *utils.AtomicTime
	IO           udpIO

	DialFunc func(addr string, firstMsgData []byte) (conn UDPConn, actualAddr string, err error)
	ExitFunc func(err error)

	conn     UDPConn
	connLock sync.Mutex
	closed   bool
	workers  *sync.WaitGroup
}

func newUDPSessionEntry(
	id uint32, requestID uint64, io udpIO,
	dialFunc func(string, []byte) (UDPConn, string, error),
	exitFunc func(error),
) (e *udpSessionEntry) {
	e = &udpSessionEntry{
		ID:      id,
		Request: RequestInfo{ID: requestID, Network: "udp", AssociationID: id},
		D:       &frag.Defragger{},
		Last:    utils.NewAtomicTime(time.Now()),
		IO:      io,

		DialFunc: dialFunc,
		ExitFunc: exitFunc,
	}

	return e
}

// CloseWithErr closes the session and calls ExitFunc with the given error.
// A nil error indicates the session is cleaned up due to timeout.
func (e *udpSessionEntry) CloseWithErr(err error) {
	// We need this lock to ensure not to create conn after session exit
	e.connLock.Lock()

	if e.closed {
		// Already closed
		e.connLock.Unlock()
		return
	}

	e.closed = true
	if e.conn != nil {
		_ = e.conn.Close()
	}
	e.connLock.Unlock()

	e.ExitFunc(err)
}

// Feed feeds a UDP message to the session.
// If the message itself is a complete message, or it completes a fragmented message,
// the message is written to the session's UDP connection, and the number of bytes
// written is returned.
// Otherwise, 0 and nil are returned.
func (e *udpSessionEntry) Feed(msg *protocol.UDPMessage) (int, error) {
	e.Last.Set(time.Now())
	dfMsg := e.D.Feed(msg)
	if dfMsg == nil {
		return 0, nil
	}

	if e.conn == nil {
		err := e.initConn(dfMsg)
		if err != nil {
			return 0, err
		}
	}

	addr := dfMsg.Addr
	if e.OverrideAddr != "" {
		addr = e.OverrideAddr
	}

	return e.conn.WriteTo(dfMsg.Data, addr)
}

// initConn initializes the UDP connection of the session.
// If no error is returned, the e.conn is set to the new connection.
func (e *udpSessionEntry) initConn(firstMsg *protocol.UDPMessage) error {
	// We need this lock to ensure not to create conn after session exit
	e.connLock.Lock()

	if e.closed {
		e.connLock.Unlock()
		return errors.New("session is closed")
	}

	e.Request.Target = firstMsg.Addr
	conn, actualAddr, err := e.DialFunc(firstMsg.Addr, firstMsg.Data)
	if err != nil {
		// Fail fast if DialFunc failed
		// (usually indicates the connection has been rejected by the ACL)
		e.connLock.Unlock()
		// CloseWithErr acquires the connLock again
		e.CloseWithErr(err)
		return err
	}

	e.conn = conn

	if firstMsg.Addr != actualAddr {
		// Hook changed the address, enable address override
		e.OverrideAddr = actualAddr
		e.OriginalAddr = firstMsg.Addr
	}
	if e.workers != nil {
		e.workers.Add(1)
		go func() {
			defer e.workers.Done()
			e.receiveLoop()
		}()
	} else {
		go e.receiveLoop()
	}

	e.connLock.Unlock()
	return nil
}

// receiveLoop receives incoming UDP packets, packs them into UDP messages,
// and sends using the IO.
// Exit when either the underlying UDP connection returns error (e.g. closed),
// or the IO returns error when sending.
func (e *udpSessionEntry) receiveLoop() {
	udpBuf := make([]byte, protocol.MaxUDPSize)
	msgBuf := make([]byte, protocol.MaxUDPSize)
	for {
		udpN, rAddr, err := e.conn.ReadFrom(udpBuf)
		if err != nil {
			e.CloseWithErr(err)
			return
		}
		e.Last.Set(time.Now())

		if e.OriginalAddr != "" {
			// Use the original address in the opposite direction,
			// otherwise the QUIC clients or NAT on the client side
			// may not treat it as the same UDP session.
			rAddr = e.OriginalAddr
		}

		msg := &protocol.UDPMessage{
			SessionID: e.ID,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      rAddr,
			Data:      udpBuf[:udpN],
		}
		err = sendMessageAutoFrag(e.IO, e.Request, msgBuf, msg)
		if err != nil {
			e.CloseWithErr(err)
			return
		}
	}
}

// sendMessageAutoFrag tries to send a UDP message as a whole first,
// but if it fails due to quic.ErrMessageTooLarge, it tries again by
// fragmenting the message.
func sendMessageAutoFrag(io udpIO, request RequestInfo, buf []byte, msg *protocol.UDPMessage) error {
	send := io.SendMessage
	if sessionIO, ok := io.(sessionUDPIO); ok {
		send = func(buf []byte, msg *protocol.UDPMessage) error {
			return sessionIO.SendMessageContext(request, buf, msg)
		}
	}
	err := send(buf, msg)
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize))
		for _, fMsg := range fMsgs {
			err := send(buf, &fMsg)
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		return err
	}
}

// udpSessionManager manages the lifecycle of UDP sessions.
// Each UDP session is identified by a SessionID, and corresponds to a UDP connection.
// A UDP session is created when a UDP message with a new SessionID is received.
// Similar to standard NAT, a UDP session is destroyed when no UDP message is received
// for a certain period of time (specified by idleTimeout).
type udpSessionManager struct {
	io          udpIO
	eventLogger udpEventLogger
	idleTimeout time.Duration
	nextRequest func() uint64
	requestID   atomic.Uint64
	workers     sync.WaitGroup

	mutex sync.RWMutex
	m     map[uint32]*udpSessionEntry
}

func newUDPSessionManager(io udpIO, eventLogger udpEventLogger, idleTimeout time.Duration, generators ...func() uint64) *udpSessionManager {
	m := &udpSessionManager{
		io:          io,
		eventLogger: eventLogger,
		idleTimeout: idleTimeout,
		m:           make(map[uint32]*udpSessionEntry),
	}
	if len(generators) > 0 && generators[0] != nil {
		m.nextRequest = generators[0]
	} else {
		m.nextRequest = func() uint64 { return m.requestID.Add(1) }
	}
	return m
}

// Run runs the session manager main loop.
// Exit and returns error when the underlying io returns error (e.g. closed).
func (m *udpSessionManager) Run() error {
	stopCh := make(chan struct{})
	m.workers.Add(1)
	go func() {
		defer m.workers.Done()
		m.idleCleanupLoop(stopCh)
	}()
	defer func() {
		close(stopCh)
		m.cleanup(false)
		m.workers.Wait()
	}()

	for {
		msg, err := m.io.ReceiveMessage()
		if err != nil {
			return err
		}
		if err := m.feed(msg); err != nil {
			return err
		}
	}
}

func (m *udpSessionManager) idleCleanupLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(idleCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.cleanup(true)
		case <-stopCh:
			return
		}
	}
}

func (m *udpSessionManager) cleanup(idleOnly bool) {
	// We use RLock here as we are only scanning the map, not deleting from it.
	m.mutex.RLock()
	timeoutEntry := make([]*udpSessionEntry, 0, len(m.m))
	now := time.Now()
	for _, entry := range m.m {
		if !idleOnly || now.Sub(entry.Last.Get()) > m.idleTimeout {
			timeoutEntry = append(timeoutEntry, entry)
		}
	}
	m.mutex.RUnlock()

	for _, entry := range timeoutEntry {
		// This eventually calls entry.ExitFunc,
		// where the m.mutex will be locked again to remove the entry from the map.
		entry.CloseWithErr(nil)
	}
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) error {
	m.mutex.RLock()
	entry := m.m[msg.SessionID]
	m.mutex.RUnlock()

	// Create a new session if not exists
	if entry == nil {
		dialFunc := func(addr string, firstMsgData []byte) (conn UDPConn, actualAddr string, err error) {
			// Call the hook
			err = m.io.Hook(firstMsgData, &addr)
			if err != nil {
				return conn, actualAddr, err
			}
			actualAddr = addr
			entry.Request.Target = addr
			// Log the event
			if sessionLogger, ok := m.eventLogger.(sessionUDPEventLogger); ok {
				sessionLogger.NewSession(entry.Request)
			} else {
				m.eventLogger.New(entry.ID, addr)
			}
			// Dial target
			if sessionIO, ok := m.io.(sessionUDPIO); ok {
				conn, err = sessionIO.UDPContext(entry.Request)
			} else {
				conn, err = m.io.UDP(addr)
			}
			return conn, actualAddr, err
		}
		exitFunc := func(err error) {
			// Log the event
			if sessionLogger, ok := m.eventLogger.(sessionUDPEventLogger); ok {
				sessionLogger.CloseSession(entry.Request, err)
			} else {
				m.eventLogger.Close(entry.ID, err)
			}

			// Remove the session from the map
			m.mutex.Lock()
			delete(m.m, entry.ID)
			m.mutex.Unlock()
		}

		entry = newUDPSessionEntry(msg.SessionID, m.nextRequest(), m.io, dialFunc, exitFunc)
		entry.workers = &m.workers
		entry.Request.Target = msg.Addr

		// Insert the session into the map
		m.mutex.Lock()
		m.m[msg.SessionID] = entry
		m.mutex.Unlock()
	}
	if sessionIO, ok := m.io.(sessionUDPIO); ok {
		if !sessionIO.Admit(entry.Request, msg, uint64(len(msg.Data)), 0) {
			entry.CloseWithErr(errDisconnect)
			return errDisconnect
		}
	}

	// Feed the message to the session
	// Feed (send) errors are ignored for now,
	// as some are temporary (e.g. invalid address)
	_, _ = entry.Feed(msg)
	return nil
}

func (m *udpSessionManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m)
}
