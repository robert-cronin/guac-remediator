# Architecture

this poc merges two responsibilities:

1. **Aggregator**

   - polls guac on a schedule to discover vulnerabilities (cves) tied to artifacts (pURLs).
   - stores a lightweight mapping in a local data store (in-memory or sqlite).

2. **Remediator**
   - listens for newly discovered or updated vulnerabilities.
   - dispatches a configured remediator (e.g., copa) to patch artifacts.
   - tracks remediation states in a simple fsm: pending, in_progress, completed, failed, escalated.
