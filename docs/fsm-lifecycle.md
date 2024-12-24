# Finite State Machine (FSM) Lifecycle

Remediation workflows progress through well-defined states. This project uses a FSM to ensure consistency, support retries, and handle escalations.

## States

- **PENDING:** A vulnerability is known, but remediation has not begun.
- **IN_PROGRESS:** Steps of the chosen remediator are currently executing.
- **COMPLETED:** All steps succeeded, and the instance is remediated.
- **FAILED:** Steps failed, and policy may trigger retries, fallback remediators, or manual intervention.
- **ESCALATED:** Multiple failed attempts lead to escalation, notifying operators or switching to a different remediation strategy.

## Transitions

- `PENDING` → `IN_PROGRESS`: Remediation started.
- `IN_PROGRESS` → `COMPLETED`: All steps done successfully.
- `IN_PROGRESS` → `FAILED`: A step failed and no retries remain.
- `FAILED` → `ESCALATED`: If severity warrants and retry limit reached.
- `COMPLETED` → `DEESCALATE`: If a new version is “certified good” by GUAC, GUARDIAN can clear the alert or lower the priority.

## Visualization
```
 PENDING ---> IN_PROGRESS ---> COMPLETED
    |            |                 ^
    |            v                 |
    |          FAILED ----> ESCALATED
    |
    ---> DEESCALATE (When upstream fix is found)
```