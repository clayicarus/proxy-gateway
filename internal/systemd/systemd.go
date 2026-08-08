// Package systemd contains the small, privilege-scoped integration used by
// the Gateway process. systemd itself remains the process supervisor.
package systemd

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	managerBusName = "org.freedesktop.systemd1"
	managerPath    = dbus.ObjectPath("/org/freedesktop/systemd1")
)

// RestartUnit requests a systemd restart using the system bus. The unit name
// is deliberately constrained to a simple .service unit to prevent a local
// management form from gaining arbitrary systemd control.
func RestartUnit(unit string) error {
	if !validUnit(unit) {
		return fmt.Errorf("invalid systemd unit %q", unit)
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return fmt.Errorf("connect system bus: %w", err)
	}
	defer conn.Close()
	var job dbus.ObjectPath
	call := conn.Object(managerBusName, managerPath).Call("org.freedesktop.systemd1.Manager.RestartUnit", 0, unit, "replace")
	if call.Err != nil {
		return fmt.Errorf("restart %s: %w", unit, call.Err)
	}
	if err := call.Store(&job); err != nil {
		return fmt.Errorf("decode restart job: %w", err)
	}
	return nil
}

func validUnit(unit string) bool {
	if !strings.HasSuffix(unit, ".service") || len(unit) > 128 {
		return false
	}
	for _, char := range unit {
		if !(char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-' || char == '@') {
			return false
		}
	}
	return true
}

// ServiceStatus is the subset needed by the local management UI.
type ServiceStatus struct {
	ActiveState     string
	SubState        string
	MainPID         uint32
	Result          string
	NRestarts       uint32
	ActiveEnterUSec uint64
}

// Status reads the service properties exposed by systemd.
func Status(unit string) (ServiceStatus, error) {
	if !validUnit(unit) {
		return ServiceStatus{}, fmt.Errorf("invalid systemd unit %q", unit)
	}
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return ServiceStatus{}, err
	}
	defer conn.Close()
	var path dbus.ObjectPath
	if err := conn.Object(managerBusName, managerPath).Call("org.freedesktop.systemd1.Manager.GetUnit", 0, unit).Store(&path); err != nil {
		return ServiceStatus{}, err
	}
	unitObject := conn.Object(managerBusName, path)
	var unitProps, serviceProps map[string]dbus.Variant
	if err := unitObject.Call("org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.systemd1.Unit").Store(&unitProps); err != nil {
		return ServiceStatus{}, err
	}
	if err := unitObject.Call("org.freedesktop.DBus.Properties.GetAll", 0, "org.freedesktop.systemd1.Service").Store(&serviceProps); err != nil {
		return ServiceStatus{}, err
	}
	return ServiceStatus{
		ActiveState:     stringProperty(unitProps, "ActiveState"),
		SubState:        stringProperty(unitProps, "SubState"),
		MainPID:         uint32Property(serviceProps, "MainPID"),
		Result:          stringProperty(serviceProps, "Result"),
		NRestarts:       uint32Property(serviceProps, "NRestarts"),
		ActiveEnterUSec: uint64Property(unitProps, "ActiveEnterTimestampMonotonic"),
	}, nil
}

func stringProperty(props map[string]dbus.Variant, key string) string {
	if value, ok := props[key].Value().(string); ok {
		return value
	}
	return ""
}

func uint32Property(props map[string]dbus.Variant, key string) uint32 {
	switch value := props[key].Value().(type) {
	case uint32:
		return value
	case uint64:
		return uint32(value)
	default:
		return 0
	}
}

func uint64Property(props map[string]dbus.Variant, key string) uint64 {
	switch value := props[key].Value().(type) {
	case uint64:
		return value
	case uint32:
		return uint64(value)
	default:
		return 0
	}
}

// Notify sends a datagram to systemd's NOTIFY_SOCKET. It is a no-op outside a
// systemd service, which keeps local development simple.
func Notify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	if strings.HasPrefix(socket, "@") {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer conn.Close()
	_, err = conn.Write([]byte(state))
	return err
}

// WatchdogInterval returns half of WATCHDOG_USEC, as systemd recommends.
func WatchdogInterval() time.Duration {
	value := os.Getenv("WATCHDOG_USEC")
	microseconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil || microseconds == 0 {
		return 0
	}
	return time.Duration(microseconds/2) * time.Microsecond
}
