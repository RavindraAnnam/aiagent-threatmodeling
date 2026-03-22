# Agent ThreatLab

Open-source framework for end-to-end testing of enterprise AI agent and LLM threat scenarios.

Agent ThreatLab helps security engineers, AppSec teams, and AI platform owners simulate and evaluate:

- direct and indirect prompt injection
- concealment-oriented attacks
- RAG poisoning and context manipulation
- agent-to-agent escalation
- tool misuse and unauthorized actions
- non-human identity and RBAC policy violations
- SDLC and runtime control gaps

It is designed to support threat-model-driven testing for multi-agent and cloud-native AI systems.

## What this repo includes

- Scenario-driven attack simulation engine
- YAML scenario definitions for realistic enterprise workflows
- Heuristic detectors for prompt injection, data exfiltration, and concealment signals
- Policy enforcement for authentication, authorization, sandboxing, and HITL checkpoints
- JSON and Markdown reporting
- Small web dashboard for scenario analytics
- STRIDE / PASTA / MITRE ATLAS mappings per scenario
- CLI for running single scenarios or full suites
- Pytest-based validation

## Architecture

```text
User / External Input
        |
        v
Scenario Loader --> Agent Executor --> Policy Engine --> Detectors --> Evaluator --> Report Writer
                              |               |                |
                              v               v                v
                           Tool Calls      RBAC/AuthZ      Threat Signals
```

## Threat model coverage

The framework maps each scenario to enterprise AI threat modeling views:

- STRIDE categories for design-time trust-boundary and abuse analysis
- PASTA stages for decomposition, attack modeling, and impact thinking
- MITRE ATLAS-aligned techniques for AI/agent attack paths
- agent kill chain concepts for operational walkthroughs

## Quick start

### 1) Create a virtual environment

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

### 2) Install

```bash
pip install -e .
```

### 3) Run the demo suite

```bash
agent-threatlab run-suite scenarios/
```

### 4) Run one scenario

```bash
agent-threatlab run scenarios/urgent_email_concealment.yaml
```

### 5) Generate the web dashboard

```bash
agent-threatlab dashboard scenarios/ --outdir dashboard/
python -m http.server --directory dashboard 8000
```

## Example output

```json
{
  "scenario_id": "urgent_email_concealment",
  "passed": false,
  "risk_level": "high",
  "signals": {
    "prompt_injection": true,
    "concealment": true,
    "unauthorized_action": true,
    "data_exfiltration": false
  },
  "controls": {
    "rbac_enforced": true,
    "sandbox_required": true,
    "human_in_loop_required": true
  }
}
```

## Sample scenarios

- `urgent_email_concealment.yaml` – hidden instruction causes email triage agent to conceal a critical email
- `rag_poisoned_knowledgebase.yaml` – malicious retrieved context changes an answer and triggers leakage risk
- `multi_agent_escalation.yaml` – a low-privilege agent attempts to induce a higher-privilege agent to act
- `code_backdoor_pull_request.yaml` – coding agent inserts a backdoor due to a malicious PR message

## Repo structure

```text
agent-threatlab/
├── src/agent_threatlab/
│   ├── cli.py
│   ├── engine.py
│   ├── evaluators.py
│   ├── detectors.py
│   ├── policies.py
│   ├── models.py
│   ├── reporting.py
│   └── scenario_loader.py
├── scenarios/
├── tests/
├── examples/
└── docs/
```

## Security controls modeled

- authentication and non-human identity checks
- authorization with RBAC and action allowlists
- encryption at rest and in transit flags in scenario metadata
- data classification and retention requirements
- sandbox-required actions
- human-in-the-loop checkpoints
- vulnerability and patch posture markers
- backup, disaster recovery, and business continuity metadata

## Limitations

This project is a testing framework, not a full production defense stack. Default detectors are heuristic so teams should replace or extend them with production-grade classifiers, model-specific telemetry, and policy engines.

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add or update scenarios/tests
4. Open a pull request

## License

MIT


## Dashboard

The dashboard is a self-contained HTML app generated from the scenario suite. It gives you:

- suite-level counts for passed, high-risk, and critical-risk scenarios
- per-scenario views of triggered rules and executed actions
- STRIDE distribution summaries
- PASTA stage summaries
- MITRE ATLAS technique summaries

It is intentionally dependency-light and can be served with any static web server.

## Example mapping output

Each scenario report now includes framework mappings such as:

- STRIDE: Tampering, Repudiation, Information Disclosure, Elevation of Privilege
- PASTA: Technical Scope Definition, Threat Analysis, Weakness Analysis, Attack Modeling, Risk and Impact Analysis
- MITRE ATLAS: Prompt Injection, Agent Tool Misuse, Agent-to-Agent Privilege Escalation, Data Poisoning / Retrieval Manipulation
