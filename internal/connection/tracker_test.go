package connection

import (
	"net"
	"testing"
)

func TestTrackerConnectionAndRequestLifecycle(t *testing.T) {
	tracker := NewTracker()
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 54321}
	tracker.Connect(addr, "alice:node1")
	tracker.StartTCP(addr, "example.com:443")
	tracker.StartTCP(addr, "example.com:443")
	tracker.StartUDP(addr, 7, "dns.example:53")

	snapshots := tracker.Snapshots()
	if len(snapshots) != 1 || snapshots[0].ClientIP != "192.0.2.10" || snapshots[0].Username != "alice" || snapshots[0].Node != "node1" {
		t.Fatalf("unexpected connection snapshot: %#v", snapshots)
	}
	if len(snapshots[0].Requests) != 3 {
		t.Fatalf("request count = %d, want 3", len(snapshots[0].Requests))
	}

	tracker.StopTCP(addr, "example.com:443")
	tracker.StopUDP(addr, 7)
	if got := len(tracker.Snapshots()[0].Requests); got != 1 {
		t.Fatalf("request count after partial close = %d, want 1", got)
	}
	tracker.Disconnect(addr)
	if got := tracker.Snapshots(); len(got) != 0 {
		t.Fatalf("connections after disconnect: %#v", got)
	}
}

func TestTrackerUsesStableSessionAndRequestIDs(t *testing.T) {
	tracker := NewTracker()
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.20"), Port: 443}
	tracker.ConnectSession("in-a/1", "in-a", addr, "alice:direct")
	tracker.ConnectSession("in-b/1", "in-b", addr, "bob:node1")
	tracker.StartRequest("in-a/1", 9, "TCP", "same.example:443")
	tracker.StartRequest("in-a/1", 10, "TCP", "same.example:443")
	tracker.StartRequest("in-b/1", 9, "UDP", "same.example:443")

	tracker.StopRequest("in-a/1", 9)
	snapshots := tracker.Snapshots()
	if len(snapshots) != 2 {
		t.Fatalf("session count = %d, want 2", len(snapshots))
	}
	byID := make(map[string]Snapshot, len(snapshots))
	for _, snapshot := range snapshots {
		byID[snapshot.SessionID] = snapshot
	}
	if got := byID["in-a/1"]; got.Inbound != "in-a" || len(got.Requests) != 1 || got.Requests[0].ID != 10 {
		t.Fatalf("unexpected first session: %#v", got)
	}
	if got := byID["in-b/1"]; got.Inbound != "in-b" || len(got.Requests) != 1 || got.Requests[0].ID != 9 {
		t.Fatalf("unexpected second session: %#v", got)
	}
	tracker.DisconnectSession("in-a/1")
	if got := tracker.Snapshots(); len(got) != 1 || got[0].SessionID != "in-b/1" {
		t.Fatalf("wrong session removed: %#v", got)
	}
}
