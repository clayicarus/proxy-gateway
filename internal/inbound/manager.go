// Package inbound coordinates protocol listener lifecycles without owning
// policy, storage, or outbound resources.
package inbound

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// Service is a constructed protocol listener with a bounded shutdown path.
type Service interface {
	Name() string
	Serve() error
	Close() error
	Wait(context.Context) error
}

// Manager owns only the lifecycle of constructed inbounds.
type Manager struct {
	services []Service
	start    sync.Once
	close    sync.Once
	errs     chan error
	closeErr error
}

func NewManager(services ...Service) *Manager {
	return &Manager{services: append([]Service(nil), services...)}
}

func (m *Manager) Add(service Service) {
	if service == nil {
		return
	}
	m.services = append(m.services, service)
}

func (m *Manager) Start() <-chan error {
	m.start.Do(func() {
		m.errs = make(chan error, len(m.services))
		for _, service := range m.services {
			go func(service Service) {
				err := service.Serve()
				if err == nil {
					err = fmt.Errorf("serve loop stopped without an error")
				}
				m.errs <- fmt.Errorf("inbound %s stopped: %w", service.Name(), err)
			}(service)
		}
	})
	return m.errs
}

func (m *Manager) Close() error {
	m.close.Do(func() {
		for _, service := range m.services {
			m.closeErr = errors.Join(m.closeErr, service.Close())
		}
	})
	return m.closeErr
}

func (m *Manager) Wait(ctx context.Context) error {
	var workers sync.WaitGroup
	errs := make(chan error, len(m.services))
	for _, service := range m.services {
		workers.Add(1)
		go func(service Service) {
			defer workers.Done()
			errs <- service.Wait(ctx)
		}(service)
	}
	done := make(chan struct{})
	go func() { workers.Wait(); close(done) }()
	select {
	case <-done:
		close(errs)
		var result error
		for err := range errs {
			result = errors.Join(result, err)
		}
		return result
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Len() int { return len(m.services) }
