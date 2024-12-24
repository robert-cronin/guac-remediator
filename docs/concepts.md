# Concepts

## Artifact & pURL

an artifact is identified by a package url (pURL). the aggregator associates vulnerabilities (cves) with specific pURLs.

## Vulnerability

a cve or end-of-life alert discovered via guac. includes severity and metadata.

## Remediation Workflow

when a vulnerability is found on a pURL, we attempt remediation using a chosen remediator (e.g., copa). the workflow transitions through states.

## Remediator Interface

a standardized set of methods each patch strategy must implement, so the remediator orchestrator can invoke them without special-case logic.
