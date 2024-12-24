package store

// TODO: extract into types or reuse guac types

// vulnerabilityrecord
type VulnerabilityRecord struct {
	ID           string
	Severity     string
	Title        string
	Purl         string
	DiscoveredAt int64
}
type Store interface {
	SaveVulnerabilityRecords(records []VulnerabilityRecord) error
}
