package store

import (
	"context"
	"fmt"
	"sync"
)

// implement the Store interface
var _ Store = &mockStore{}

// mockStore is an in-memory store with basic concurrency safety.
type mockStore struct {
	mu   sync.Mutex
	data map[string]VulnerabilityRecord
}

func NewMockStore() *mockStore {
	return &mockStore{
		data: make(map[string]VulnerabilityRecord),
	}
}

func (m *mockStore) SaveVulnerabilityRecords(ctx context.Context, records []VulnerabilityRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, r := range records {
		if _, found := m.data[r.ID]; found {
			// TODO: implement update logic
			continue
		}
		m.data[r.ID] = r
		fmt.Printf("stored vulnerability: %s\n", r.ID)
	}
	return nil
}
