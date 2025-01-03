package remediator

import (
	"context"
	"fmt"

	"github.com/robert-cronin/guac-remediator/internal/event"
	"github.com/robert-cronin/guac-remediator/internal/store"
)

// RemediationManager orchestrates the entire
// "decide → launch → track" flow for patches.
type RemediationManager struct {
	remediator Remediator
	eventBus   *event.EventBus
}

// NewRemediationManager constructs a manager with the given remediator & event bus.
func NewRemediationManager(rem Remediator, bus *event.EventBus) *RemediationManager {
	return &RemediationManager{
		remediator: rem,
		eventBus:   bus,
	}
}

// HandleVulnerability decides if/when to start a remediation workflow
func (m *RemediationManager) HandleVulnerability(ctx context.Context, r store.VulnerabilityRecord) {
	// decide if we should remediate
	if shouldRemediate(r) {
		// create a workflow
		wf, err := m.remediator.StartRemediation(StartRemediationParams{
			Vulnerability: r.CertifyVuln,
			AuthCtx:       AuthContext{},
		})
		if err != nil {
			fmt.Println("failed to start remediation:", err)
			return
		}
		fmt.Printf("created workflow %s\n", wf.WorkflowID)

		// TODO: publish an "REMEDIATION_STARTED" event
		m.eventBus.Publish(ctx, event.Event{
			Type: event.RemediationStarted,
			Data: map[string]interface{}{
				"workflow_id": wf.WorkflowID,
			},
		})
	}
}

// shouldRemediate returns true if the vulnerability should be remediated
func shouldRemediate(r store.VulnerabilityRecord) bool {
	return true
}
