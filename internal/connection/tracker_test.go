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

func TestTrackerSeparatesTCPAndUDPPeersWithSameAddress(t *testing.T) {
	tracker := NewTracker()
	udp := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 54321}
	tcp := &net.TCPAddr{IP: udp.IP, Port: udp.Port}
	tracker.Connect(udp, "alice:node1")
	tracker.StartTCP(udp, "hy2-target.example:443")
	tracker.Connect(tcp, "bob:direct")
	tracker.StartTCP(tcp, "trojan-target.example:443")
	if got := tracker.Snapshots(); len(got) != 2 {
		t.Fatalf("TCP and UDP peers overwrote each other: %d sessions", len(got))
	}
	tracker.StopTCP(tcp, "trojan-target.example:443")
	tracker.Disconnect(tcp)
	remaining := tracker.Snapshots()
	if len(remaining) != 1 || remaining[0].Username != "alice" || len(remaining[0].Requests) != 1 || remaining[0].Requests[0].Target != "hy2-target.example:443" {
		t.Fatal("closing a Trojan peer changed the Hysteria2 session")
	}
	tracker.StopTCP(udp, "hy2-target.example:443")
	tracker.Disconnect(udp)
	if len(tracker.Snapshots()) != 0 {
		t.Fatal("Hysteria2 session remained after disconnect")
	}
}
