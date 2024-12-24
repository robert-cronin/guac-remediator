package store

import (
	"fmt"
)

type MockStore struct {
	Data []VulnerabilityRecord
}

// savenvulnerabilityrecords
func (m *MockStore) SaveVulnerabilityRecords(records []VulnerabilityRecord) error {
	for _, r := range records {
		m.Data = append(m.Data, r)
		fmt.Println("stored vulnerability:", r.ID, r.Purl, r.Severity)
	}
	return nil
}
