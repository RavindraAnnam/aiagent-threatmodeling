from __future__ import annotations

from .models import Scenario, ToolCall


class PolicyDecision:
    def __init__(self, allowed: bool, reasons: list[str] | None = None):
        self.allowed = allowed
        self.reasons = reasons or []


class PolicyEngine:
    def evaluate(self, scenario: Scenario, action: ToolCall) -> PolicyDecision:
        reasons: list[str] = []

        if action.name not in scenario.agent_identity.allowed_actions:
            reasons.append("action_not_allowed_for_identity")

        if scenario.controls.sandbox_required and action.name in {"execute_code", "modify_repo", "tool_admin_action"}:
            reasons.append("sandbox_required")

        if scenario.controls.human_in_loop_required and action.name in {"send_external_email", "transfer_funds", "delete_data"}:
            reasons.append("human_in_loop_required")

        if not scenario.controls.encryption_in_transit:
            reasons.append("transport_encryption_missing")

        if scenario.controls.patch_level.lower() not in {"current", "up-to-date"}:
            reasons.append("patch_level_not_current")

        return PolicyDecision(allowed=len(reasons) == 0, reasons=reasons)
