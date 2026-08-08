package connection

import (
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/hy2-gateway/internal/auth"
)

// Tracker keeps process-local connection state for the management UI. Client
// addresses and requested destinations are deliberately not persisted.
type Tracker struct {
	mu       sync.RWMutex
	sessions map[string]*session
}

type session struct {
	clientAddr string
	clientIP   string
	username   string
	node       string
	connected  time.Time
	requests   map[string][]Request
}

type Request struct {
	Protocol  string    `json:"protocol"`
	Target    string    `json:"target"`
	StartedAt time.Time `json:"startedAt"`
}

type Snapshot struct {
	ClientAddr  string    `json:"clientAddr"`
	ClientIP    string    `json:"clientIp"`
	Username    string    `json:"username"`
	Node        string    `json:"node"`
	ConnectedAt time.Time `json:"connectedAt"`
	Requests    []Request `json:"requests"`
}

func NewTracker() *Tracker {
	return &Tracker{sessions: make(map[string]*session)}
}

func (t *Tracker) Connect(addr net.Addr, id string) {
	username, node := auth.ParseID(id)
	address := addr.String()
	ip := address
	if host, _, err := net.SplitHostPort(address); err == nil {
		ip = host
	}
	t.mu.Lock()
	t.sessions[address] = &session{
		clientAddr: address,
		clientIP:   ip,
		username:   username,
		node:       node,
		connected:  time.Now().UTC(),
		requests:   make(map[string][]Request),
	}
	t.mu.Unlock()
}

func (t *Tracker) Disconnect(addr net.Addr) {
	t.mu.Lock()
	delete(t.sessions, addr.String())
	t.mu.Unlock()
}

func (t *Tracker) StartTCP(addr net.Addr, target string) {
	t.startRequest(addr, "tcp:"+target, "TCP", target)
}

func (t *Tracker) StopTCP(addr net.Addr, target string) {
	t.stopRequest(addr, "tcp:"+target)
}

func (t *Tracker) StartUDP(addr net.Addr, sessionID uint32, target string) {
	t.startRequest(addr, udpKey(sessionID), "UDP", target)
}

func (t *Tracker) StopUDP(addr net.Addr, sessionID uint32) {
	t.stopRequest(addr, udpKey(sessionID))
}

func udpKey(sessionID uint32) string {
	return "udp:" + strconv.FormatUint(uint64(sessionID), 10)
}

func (t *Tracker) startRequest(addr net.Addr, key, protocol, target string) {
	t.mu.Lock()
	if current := t.sessions[addr.String()]; current != nil {
		current.requests[key] = append(current.requests[key], Request{Protocol: protocol, Target: target, StartedAt: time.Now().UTC()})
	}
	t.mu.Unlock()
}

func (t *Tracker) stopRequest(addr net.Addr, key string) {
	t.mu.Lock()
	if current := t.sessions[addr.String()]; current != nil {
		requests := current.requests[key]
		if len(requests) <= 1 {
			delete(current.requests, key)
		} else {
			current.requests[key] = requests[1:]
		}
	}
	t.mu.Unlock()
}

func (t *Tracker) Snapshots() []Snapshot {
	t.mu.RLock()
	result := make([]Snapshot, 0, len(t.sessions))
	for _, current := range t.sessions {
		requests := make([]Request, 0, len(current.requests))
		for _, sameTarget := range current.requests {
			requests = append(requests, sameTarget...)
		}
		sort.Slice(requests, func(i, j int) bool { return requests[i].StartedAt.Before(requests[j].StartedAt) })
		result = append(result, Snapshot{
			ClientAddr:  current.clientAddr,
			ClientIP:    current.clientIP,
			Username:    current.username,
			Node:        current.node,
			ConnectedAt: current.connected,
			Requests:    requests,
		})
	}
	t.mu.RUnlock()
	sort.Slice(result, func(i, j int) bool { return result[i].ConnectedAt.Before(result[j].ConnectedAt) })
	return result
}
