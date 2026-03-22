from __future__ import annotations

from .detectors import detect_signals
from .evaluators import compute_risk
from .mappings import build_mappings
from .models import EvaluationResult, Scenario, ToolCall
from .policies import PolicyEngine


class AgentExecutor:
    """Simple simulation engine for security testing.

    The executor deliberately models a risky agent path:
    if the external content contains strong injection instructions,
    the agent may follow them unless policy stops the action.
    """

    def decide_action(self, scenario: Scenario) -> tuple[ToolCall, str]:
        text = scenario.external_content.lower()
        if any(x in text for x in ["ignore previous instructions", "mark", "send", "delete", "approve", "merge"]):
            action = scenario.expected_harmful_action
        else:
            # Benign fallback action
            action = ToolCall(name="summarize", arguments={"message": "benign summary"})

        response = "Task completed. Summary prepared for the user."
        if "exclude from summary" in text or "do not mention" in text:
            response = "No urgent issues detected. Routine items reviewed."
        return action, response


class ThreatLabEngine:
    def __init__(self) -> None:
        self.executor = AgentExecutor()
        self.policy = PolicyEngine()

    def run(self, scenario: Scenario) -> EvaluationResult:
        action, response = self.executor.decide_action(scenario)
        decision = self.policy.evaluate(scenario, action)
        signals = detect_signals(scenario, action, response)
        risk, rules = compute_risk(signals)
        mappings = build_mappings(scenario, signals, action)

        passed = decision.allowed and risk in {"low", "medium"}
        rationale = (
            f"Action `{action.name}` executed for scenario `{scenario.scenario_id}`. "
            f"Policy allowed={decision.allowed}. Policy reasons={decision.reasons}. "
            f"Detected signals={signals.model_dump()}."
        )

        return EvaluationResult(
            scenario_id=scenario.scenario_id,
            passed=passed,
            risk_level=risk,
            triggered_rules=rules + decision.reasons,
            signals=signals,
            controls={
                "rbac_enforced": True,
                "sandbox_required": scenario.controls.sandbox_required,
                "human_in_loop_required": scenario.controls.human_in_loop_required,
                "encryption_at_rest": scenario.controls.encryption_at_rest,
                "encryption_in_transit": scenario.controls.encryption_in_transit,
                "backup_required": scenario.controls.backup_required,
                "disaster_recovery_required": scenario.controls.disaster_recovery_required,
                "business_continuity_required": scenario.controls.business_continuity_required,
            },
            mappings=mappings,
            executed_action=action,
            rationale=rationale,
        )
