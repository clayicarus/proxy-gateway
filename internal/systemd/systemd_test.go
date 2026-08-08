package systemd

import (
	"testing"
	"time"
)

func TestValidUnit(t *testing.T) {
	for _, unit := range []string{"hy2-gateway.service", "hy2-gateway@blue.service", "a_b-1.service"} {
		if !validUnit(unit) {
			t.Fatalf("expected valid unit %q", unit)
		}
	}
	for _, unit := range []string{"", "hy2-gateway", "../other.service", "a.service;reboot", "unit.socket"} {
		if validUnit(unit) {
			t.Fatalf("expected invalid unit %q", unit)
		}
	}
}

func TestWatchdogInterval(t *testing.T) {
	t.Setenv("WATCHDOG_USEC", "30000000")
	if got := WatchdogInterval(); got != 15*time.Second {
		t.Fatalf("interval = %s, want 15s", got)
	}
	t.Setenv("WATCHDOG_USEC", "invalid")
	if got := WatchdogInterval(); got != 0 {
		t.Fatalf("invalid interval = %s, want zero", got)
	}
}
