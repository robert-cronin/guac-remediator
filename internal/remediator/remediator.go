package remediator

import (
	"fmt"

	model "github.com/guacsec/guac/pkg/assembler/clients/generated"
	"github.com/robert-cronin/guac-remediator/internal/state"
)

type Remediator interface {
	Initialize() error
	StartRemediation(params StartRemediationParams) (RemediationWorkflow, error)
	PollRemediationStatus(workflowID string) (RemediationWorkflow, error)
	Rollback(workflowID string) error
	Cleanup(workflowID string) error
}

type StartRemediationParams struct {
	Vulnerability model.AllCertifyVuln
	AuthCtx       AuthContext
}

type AuthContext struct {
	Credentials map[string]string
	Metadata    map[string]string
}

// BasicRemediator is an example that uses an fsm manager.
type BasicRemediator struct {
	fsm       *FSMManager
	workflows map[string]*RemediationWorkflow
}

// NewBasicRemediator creates a new BasicRemediator.
func NewBasicRemediator() *BasicRemediator {
	return &BasicRemediator{
		fsm:       NewFSMManager(),
		workflows: make(map[string]*RemediationWorkflow),
	}
}

// Initialize
func (br *BasicRemediator) Initialize() error {
	fmt.Println("basic remediator: initialized")
	return nil
}

// StartRemediation
func (br *BasicRemediator) StartRemediation(params StartRemediationParams) (RemediationWorkflow, error) {
	// create a new workflow
	wf := RemediationWorkflow{
		WorkflowID: "wf-" + params.Vulnerability.Vulnerability.Id,
		State:      state.StatePending,
		// mock steps
		Steps: []RemediationStep{
			{Name: "download_patch"},
			{Name: "apply_patch"},
			{Name: "verify_patch"},
		},
	}
	// store in the map
	br.workflows[wf.WorkflowID] = &wf

	err := br.fsm.StartWorkflow(&wf)
	if err != nil {
		return wf, err
	}
	// simulate something
	return wf, nil
}

// PollRemediationStatus
func (br *BasicRemediator) PollRemediationStatus(workflowID string) (RemediationWorkflow, error) {
	wf, ok := br.workflows[workflowID]
	if !ok {
		return RemediationWorkflow{}, fmt.Errorf("workflow %s not found", workflowID)
	}

	// in a real scenario, we might check step statuses or external logs, etc.
	// for now, let’s just say if all steps are in_progress, we complete them.
	allStepsInProgress := true
	for _, step := range wf.Steps {
		if step.Status != state.StateInProgress {
			allStepsInProgress = false
			break
		}
	}
	if allStepsInProgress {
		// transition to completed
		_ = br.fsm.CompleteWorkflow(wf)
	}

	return *wf, nil
}

// Rollback
func (br *BasicRemediator) Rollback(workflowID string) error {
	wf, ok := br.workflows[workflowID]
	if !ok {
		return fmt.Errorf("workflow %s not found", workflowID)
	}
	// handle rollback logic, e.g. revert changes
	br.fsm.FailWorkflow(wf)
	return nil
}

// Cleanup
func (br *BasicRemediator) Cleanup(workflowID string) error {
	wf, ok := br.workflows[workflowID]
	if !ok {
		return fmt.Errorf("workflow %s not found", workflowID)
	}

	if wf.State != state.StateCompleted && wf.State != state.StateFailed {
		return fmt.Errorf("cleanup only allowed on completed or failed workflows, current: %s", wf.State)
	}
	// remove from map or free resources
	delete(br.workflows, workflowID)
	fmt.Printf("cleaned up workflow: %s\n", workflowID)
	return nil
}
