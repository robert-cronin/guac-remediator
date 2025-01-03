package event

import (
	"context"
	"sync"
)

type EventType string

const (
	VulnDiscovered     EventType = "VULN_DISCOVERED"
	RemediationStarted EventType = "REMEDIATION_STARTED"
	PatchComplete      EventType = "PATCH_COMPLETE"
)

// Event holds basic info about what's happening in the system.
type Event struct {
	Type EventType
	Data map[string]interface{}
}

// Handler is anything that can receive events.
type Handler interface {
	HandleEvent(ctx context.Context, e Event)
}

// EventBus is a simple pub/sub system for dispatching events.
type EventBus struct {
	mu          sync.RWMutex
	subscribers []Handler
}

// NewEventBus returns a fresh EventBus.
func NewEventBus() *EventBus {
	return &EventBus{}
}

// Subscribe registers a handler to receive published events.
func (bus *EventBus) Subscribe(h Handler) {
	bus.mu.Lock()
	defer bus.mu.Unlock()
	bus.subscribers = append(bus.subscribers, h)
}

// Publish sends an event to all subscribers (synchronously in this POC).
func (bus *EventBus) Publish(ctx context.Context, e Event) {
	bus.mu.RLock()
	defer bus.mu.RUnlock()

	// For a simple POC, we handle events synchronously (no goroutines).
	for _, sub := range bus.subscribers {
		sub.HandleEvent(ctx, e)
	}
}
