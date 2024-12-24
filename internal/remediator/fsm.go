package remediator

import (
	"errors"
	"time"

	"github.com/robert-cronin/guac-remediator/internal/state"
)

type FSMManager struct{}

// NewFSMManager returns an FSMManager
func NewFSMManager() *FSMManager {
	return &FSMManager{}
}

// StartWorkflow transitions from PENDING to IN_PROGRESS
func (f *FSMManager) StartWorkflow(w *RemediationWorkflow) error {
	if w.State != state.StatePending {
		return errors.New("workflow not in pending state")
	}
	w.State = state.StateInProgress
	// set step statuses to "IN_PROGRESS" if not already set
	for i := range w.Steps {
		if w.Steps[i].Status == "" {
			w.Steps[i].Status = state.StateInProgress
		}
	}
	return nil
}

// CompleteWorkflow transitions from IN_PROGRESS to COMPLETED
func (f *FSMManager) CompleteWorkflow(w *RemediationWorkflow) error {
	if w.State != state.StateInProgress {
		return errors.New("workflow not in progress state")
	}
	w.State = state.StateCompleted
	for i := range w.Steps {
		w.Steps[i].Status = state.StateCompleted
	}
	return nil
}

// FailWorkflow transitions from IN_PROGRESS to FAILED
func (f *FSMManager) FailWorkflow(w *RemediationWorkflow) error {
	if w.State != state.StateInProgress {
		return errors.New("workflow not in progress state")
	}
	w.State = state.StateFailed
	for i := range w.Steps {
		if w.Steps[i].Status == state.StateInProgress {
			w.Steps[i].Status = state.StateFailed
		}
	}
	return nil
}

// EscalateWorkflow transitions from FAILED to ESCALATED
func (f *FSMManager) EscalateWorkflow(w *RemediationWorkflow) error {
	if w.State != state.StateFailed {
		return errors.New("workflow not in failed state")
	}
	w.State = state.StateEscalated
	return nil
}

// TODO: add more transitions. or track how many retries have passed.
func (f *FSMManager) RetryWorkflow(w *RemediationWorkflow) error {
	// if we decide to re-attempt from FAILED to IN_PROGRESS
	if w.State != state.StateFailed {
		return errors.New("workflow not in failed state, cannot retry")
	}
	w.State = state.StateInProgress
	for i := range w.Steps {
		if w.Steps[i].Status == state.StateFailed {
			w.Steps[i].Status = state.StateInProgress
		}
	}
	return nil
}

// optional: track timestamps or logs of transitions
func (f *FSMManager) MarkTransition(w *RemediationWorkflow, note string) {
	// TODO: implement
	// store some metadata about transitions if needed
	// e.g., w.Steps = append(w.Steps, RemediationStep{...})
	_ = note
	// could track times or reasons for transitions
	// e.g., time.Now().Format(time.RFC3339)
	_ = time.Now()
}
