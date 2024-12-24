# Data Structures

## Aggregator

```go
package aggregator

type VulnerabilityRecord struct {
    ID        string
    Severity  string
    Title     string
    Purl      string
    DiscoveredAt int64
}

type Aggregator interface {
    Poll() ([]VulnerabilityRecord, error)
}
```

## Remediator

```go
package remediator

type AuthContext struct {
    Credentials map[string]string
    Metadata    map[string]string
}

type StartRemediationParams struct {
    VulnerabilityID string
    Severity        string
    ArtifactPurl    string
    AuthCtx         AuthContext
}

type RemediationWorkflow struct {
    WorkflowID string
    State      string
    Steps      []RemediationStep
}

type RemediationStep struct {
    Name     string
    Status   string
    Metadata map[string]string
}

type Remediator interface {
    Initialize() error
    StartRemediation(params StartRemediationParams) (RemediationWorkflow, error)
    PollRemediationStatus(workflowID string) (RemediationWorkflow, error)
    Rollback(workflowID string) error
    Cleanup(workflowID string) error
}
```

## FSM states

```go
package state

const (
    StatePending    = "PENDING"
    StateInProgress = "IN_PROGRESS"
    StateCompleted  = "COMPLETED"
    StateFailed     = "FAILED"
    StateEscalated  = "ESCALATED"
)
```

## system store

```go
package store

type RemediationRecord struct {
    WorkflowID       string
    VulnerabilityID  string
    ArtifactPurl     string
    State            string
    Timestamp        int64
}

type Store interface {
    SaveVulnerabilityRecords(records []VulnerabilityRecord) error
    SaveRemediationRecord(rec RemediationRecord) error
    UpdateRemediationRecord(rec RemediationRecord) error
    GetRemediationRecordByWorkflowID(id string) (RemediationRecord, error)
}
```