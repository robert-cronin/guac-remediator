# GUAC Remediator

guac-remediator is a proof-of-concept system that polls [GUAC](https://github.com/guacsec/guac) for vulnerabilities and orchestrates remediation tasks (e.g., via COPA). it acts as both an aggregator (querying guac) and a remediator (executing patch workflows).

## highlights

- polls guac for new or updated vulnerabilities.
- maintains a minimal record of artifacts, vulnerabilities, and remediation attempts.
- triggers pluggable remediators for patching (e.g., copa, npm, etc.).
- tracks progress in a finite state machine (fsm) to handle retries, failures, and completions.

## quick start

1. clone this repo
2. configure guac endpoint in `config.yaml`
3. run `go run cmd/guac-remediator/main.go`
4. observe logs or the optional cli output
