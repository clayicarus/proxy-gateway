package inbound

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type testService struct {
	name   string
	serve  error
	closed bool
}

func (s *testService) Name() string { return s.name }
func (s *testService) Serve() error { return s.serve }
func (s *testService) Close() error { s.closed = true; return nil }
func (s *testService) Wait(context.Context) error {
	if !s.closed {
		return errors.New("service was not closed")
	}
	return nil
}

func TestManagerStartsAndClosesServices(t *testing.T) {
	service := &testService{name: "test", serve: errors.New("stopped")}
	manager := NewManager(service)
	errs := manager.Start()
	if err := <-errs; err == nil || err.Error() != "inbound test stopped: stopped" {
		t.Fatalf("serve error = %v", err)
	}
	if err := manager.Close(); err != nil {
		t.Fatal(err)
	}
	if err := manager.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

type errorService struct {
	name     string
	closeErr error
	waitErr  error
	closes   atomic.Int32
}

func (s *errorService) Name() string               { return s.name }
func (s *errorService) Serve() error               { return errors.New("stopped") }
func (s *errorService) Close() error               { s.closes.Add(1); return s.closeErr }
func (s *errorService) Wait(context.Context) error { return s.waitErr }

func TestManagerCloseIsIdempotentAndCollectsErrors(t *testing.T) {
	firstClose := errors.New("first close")
	secondClose := errors.New("second close")
	first := &errorService{name: "first", closeErr: firstClose}
	second := &errorService{name: "second", closeErr: secondClose}
	manager := NewManager(first, second)

	for i := 0; i < 2; i++ {
		err := manager.Close()
		if !errors.Is(err, firstClose) || !errors.Is(err, secondClose) {
			t.Fatalf("close error = %v, want both service errors", err)
		}
	}
	if first.closes.Load() != 1 || second.closes.Load() != 1 {
		t.Fatalf("close calls = %d/%d, want 1/1", first.closes.Load(), second.closes.Load())
	}
}

func TestManagerWaitCollectsServiceErrors(t *testing.T) {
	firstWait := errors.New("first wait")
	secondWait := errors.New("second wait")
	manager := NewManager(
		&errorService{name: "first", waitErr: firstWait},
		&errorService{name: "second", waitErr: secondWait},
	)
	err := manager.Wait(context.Background())
	if !errors.Is(err, firstWait) || !errors.Is(err, secondWait) {
		t.Fatalf("wait error = %v, want both service errors", err)
	}
}

type waitingService struct{}

func (waitingService) Name() string { return "waiting" }
func (waitingService) Serve() error { return errors.New("stopped") }
func (waitingService) Close() error { return nil }
func (waitingService) Wait(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func TestManagerWaitHonorsDeadline(t *testing.T) {
	manager := NewManager(waitingService{})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := manager.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait error = %v, want deadline exceeded", err)
	}
}
