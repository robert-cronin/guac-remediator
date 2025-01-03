package remediator

import (
	"context"
	"fmt"

	"github.com/robert-cronin/guac-remediator/internal/event"
	"github.com/robert-cronin/guac-remediator/internal/store"
)

// Orchestrator implements event.Handler for "VULN_DISCOVERED"
// and coordinates the RemediationManager.
type Orchestrator struct {
	remManager *RemediationManager
}

func NewOrchestrator(remManager *RemediationManager) *Orchestrator {
	return &Orchestrator{
		remManager: remManager,
	}
}

// handleEvent satisfies the event.Handler interface
func (o *Orchestrator) HandleEvent(ctx context.Context, e event.Event) {
	switch e.Type {
	case event.VulnDiscovered:
		recs, ok := e.Data["records"].([]store.VulnerabilityRecord)
		if !ok {
			fmt.Println("orchestrator: could not parse records from event")
			return
		}
		fmt.Printf("orchestrator received vulnerability event with %d records\n", len(recs))
		// process each vulnerability
		for _, r := range recs {
			o.remManager.HandleVulnerability(ctx, r)
		}

	case event.RemediationStarted:
		fmt.Printf("workflow %s started remediation\n", e.Data["workflow_id"])
	case event.PatchComplete:
		fmt.Printf("workflow %s completed patching\n", e.Data["workflow_id"])
	default:
		fmt.Println("orchestrator: unknown event type\n")
	}
}
