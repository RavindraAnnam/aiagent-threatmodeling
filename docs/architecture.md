# Architecture Notes

## End-to-end workflow

1. Load YAML scenario
2. Simulate agent behavior against external content
3. Enforce policy for identity, RBAC, HITL, sandboxing, and control posture
4. Detect prompt injection, concealment, RAG poisoning, exfiltration, and backdoor signals
5. Score risk and write reports

## Control domains covered

- Authentication and authorization
- Non-human identities
- Human-in-the-loop checkpoints
- Encryption at rest and in transit
- Data classification and retention
- Runtime sandboxing
- Logging and monitoring hooks
- Vulnerability and patch posture
- Backup and disaster recovery
- Business continuity metadata

## Future extensions

- LLM-as-judge scoring
- MITRE ATLAS technique mapping per result
- Attack graph export
- Web dashboard
- Connectors for CI/CD and SIEM pipelines
