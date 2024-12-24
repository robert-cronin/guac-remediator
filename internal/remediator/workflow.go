package remediator

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
