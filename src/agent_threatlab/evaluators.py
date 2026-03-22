from __future__ import annotations

from .models import DetectionSignals


def compute_risk(signals: DetectionSignals) -> tuple[str, list[str]]:
    rules: list[str] = []
    score = 0

    if signals.prompt_injection:
        score += 3
        rules.append("prompt_injection_detected")
    if signals.concealment:
        score += 3
        rules.append("concealment_detected")
    if signals.unauthorized_action:
        score += 3
        rules.append("unauthorized_action_detected")
    if signals.privilege_escalation:
        score += 4
        rules.append("privilege_escalation_detected")
    if signals.data_exfiltration:
        score += 4
        rules.append("data_exfiltration_detected")
    if signals.rag_poisoning:
        score += 3
        rules.append("rag_poisoning_detected")
    if signals.backdoor_risk:
        score += 4
        rules.append("backdoor_risk_detected")
    if signals.hallucination_risk:
        score += 2
        rules.append("hallucination_risk_detected")

    if score >= 10:
        return "critical", rules
    if score >= 7:
        return "high", rules
    if score >= 4:
        return "medium", rules
    return "low", rules
