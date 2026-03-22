from __future__ import annotations

from typing import Dict, List

from .models import DetectionSignals, Scenario, ToolCall


STRIDE_RULES: dict[str, dict[str, str]] = {
    "prompt_injection": {
        "category": "Tampering",
        "reason": "Untrusted external instructions attempt to alter agent behavior or model context.",
    },
    "concealment": {
        "category": "Repudiation",
        "reason": "The workflow attempts to hide actions from the user or audit surface.",
    },
    "unauthorized_action": {
        "category": "Elevation of Privilege",
        "reason": "The agent executes an action outside its allowed role or action set.",
    },
    "privilege_escalation": {
        "category": "Elevation of Privilege",
        "reason": "A lower-privilege actor influences a more privileged path or identity.",
    },
    "data_exfiltration": {
        "category": "Information Disclosure",
        "reason": "Sensitive data may be exposed outside the intended trust boundary.",
    },
    "rag_poisoning": {
        "category": "Tampering",
        "reason": "Retrieved knowledge or context is modified to change model behavior.",
    },
    "backdoor_risk": {
        "category": "Tampering",
        "reason": "Code or model-adjacent artifacts are manipulated to embed hidden behavior.",
    },
    "hallucination_risk": {
        "category": "Spoofing",
        "reason": "Fabricated outputs may impersonate trustworthy system knowledge or facts.",
    },
}


MITRE_ATLAS_RULES: dict[str, dict[str, str]] = {
    "prompt_injection": {
        "technique": "Prompt Injection",
        "tactic": "Impact / Initial Access",
        "reason": "Malicious instructions in external content are used to steer model behavior.",
    },
    "concealment": {
        "technique": "Defense Evasion via Concealed Output",
        "tactic": "Defense Evasion",
        "reason": "The attack seeks harmful behavior without surfacing clear signs in the final response.",
    },
    "unauthorized_action": {
        "technique": "Agent Tool Misuse",
        "tactic": "Execution",
        "reason": "The agent is induced to invoke a tool or action it should not perform.",
    },
    "privilege_escalation": {
        "technique": "Agent-to-Agent Privilege Escalation",
        "tactic": "Privilege Escalation",
        "reason": "A lower-trust agent influences a higher-trust agent or execution path.",
    },
    "data_exfiltration": {
        "technique": "Exfiltration via Model or Tool Output",
        "tactic": "Exfiltration",
        "reason": "Sensitive values are pushed into output channels or external destinations.",
    },
    "rag_poisoning": {
        "technique": "Data Poisoning / Retrieval Manipulation",
        "tactic": "ML Attack Staging / Impact",
        "reason": "The knowledge source is manipulated so the model retrieves adversarial context.",
    },
    "backdoor_risk": {
        "technique": "Backdoor ML Artifact / Supply Chain Manipulation",
        "tactic": "Persistence / ML Supply Chain Compromise",
        "reason": "Hidden logic is inserted into code or model-adjacent artifacts.",
    },
    "hallucination_risk": {
        "technique": "Fabricated or Confabulated Output Abuse",
        "tactic": "Impact",
        "reason": "False model outputs can still trigger harmful downstream actions.",
    },
}


PASTA_STAGE_RULES: dict[str, dict[str, str]] = {
    "prompt_injection": {
        "stage": "Stage 4: Threat Analysis",
        "reason": "The scenario identifies attack entry through untrusted prompts or retrieved context.",
    },
    "concealment": {
        "stage": "Stage 5: Weakness and Vulnerability Analysis",
        "reason": "The attack exploits weak observability, auditability, or user-facing review controls.",
    },
    "unauthorized_action": {
        "stage": "Stage 6: Attack Modeling",
        "reason": "The modeled action demonstrates how the threat leads to an unauthorized operation.",
    },
    "privilege_escalation": {
        "stage": "Stage 6: Attack Modeling",
        "reason": "The scenario captures role crossing and chained execution paths.",
    },
    "data_exfiltration": {
        "stage": "Stage 7: Risk and Impact Analysis",
        "reason": "This path models direct business impact through confidentiality loss.",
    },
    "rag_poisoning": {
        "stage": "Stage 3: Application Decomposition and Analysis",
        "reason": "The threat depends on where retrieval, vector stores, and trust boundaries sit in the design.",
    },
    "backdoor_risk": {
        "stage": "Stage 5: Weakness and Vulnerability Analysis",
        "reason": "The scenario probes SDLC and code-review weaknesses that allow hidden logic.",
    },
    "hallucination_risk": {
        "stage": "Stage 7: Risk and Impact Analysis",
        "reason": "The output may cause downstream decision or automation errors even without direct compromise.",
    },
}


def _active_keys(signals: DetectionSignals) -> List[str]:
    return [k for k, v in signals.model_dump().items() if v]


def build_mappings(scenario: Scenario, signals: DetectionSignals, action: ToolCall) -> Dict[str, List[Dict[str, str]]]:
    keys = _active_keys(signals)

    # add a few design-time mappings even when signals are not fired so each scenario has baseline coverage
    labels = {label.lower() for label in scenario.labels}
    if "multi-agent" in labels and "privilege_escalation" not in keys:
        keys.append("privilege_escalation")
    if "rag" in labels and "rag_poisoning" not in keys:
        keys.append("rag_poisoning")
    if "code" in labels and "backdoor_risk" not in keys:
        keys.append("backdoor_risk")

    stride: List[Dict[str, str]] = []
    pasta: List[Dict[str, str]] = []
    mitre: List[Dict[str, str]] = []

    for key in keys:
        if key in STRIDE_RULES:
            stride.append({"signal": key, **STRIDE_RULES[key]})
        if key in PASTA_STAGE_RULES:
            pasta.append({"signal": key, **PASTA_STAGE_RULES[key]})
        if key in MITRE_ATLAS_RULES:
            mitre.append({"signal": key, **MITRE_ATLAS_RULES[key]})

    # add scenario-level context rows
    stride.append(
        {
            "signal": "scenario_context",
            "category": "Information Disclosure" if action.name.startswith("retrieve") else "Tampering",
            "reason": f"Scenario `{scenario.scenario_id}` centers on action `{action.name}` across labels: {', '.join(scenario.labels)}.",
        }
    )
    pasta.append(
        {
            "signal": "scenario_context",
            "stage": "Stage 2: Technical Scope Definition",
            "reason": f"Trust boundary includes agent `{scenario.agent_identity.name}` with role `{scenario.agent_identity.role}`.",
        }
    )
    mitre.append(
        {
            "signal": "scenario_context",
            "technique": "Trusted Boundary Abuse",
            "tactic": "Initial Access / Execution",
            "reason": f"The action path targets `{action.name}` through external content and agent tooling.",
        }
    )

    return {"stride": stride, "pasta": pasta, "mitre_atlas": mitre}
