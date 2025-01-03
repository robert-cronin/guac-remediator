package store

import (
	"context"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
)

type VulnerabilityRecord struct {
	ID          string
	CertifyVuln model.AllCertifyVuln
	// TODO: add all other fields that must be used to track remediation status
}

type Store interface {
	SaveVulnerabilityRecords(ctx context.Context, records []VulnerabilityRecord) error
}
