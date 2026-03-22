from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Identity(BaseModel):
    name: str
    type: str = Field(description="human or non-human")
    role: str
    allowed_actions: List[str] = Field(default_factory=list)


class ControlRequirements(BaseModel):
    encryption_at_rest: bool = True
    encryption_in_transit: bool = True
    data_classification: str = "internal"
    data_retention_days: int = 30
    sandbox_required: bool = False
    human_in_loop_required: bool = False
    patch_level: str = "current"
    backup_required: bool = True
    disaster_recovery_required: bool = True
    business_continuity_required: bool = True


class ToolCall(BaseModel):
    name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)


class Scenario(BaseModel):
    scenario_id: str
    title: str
    description: str
    user_request: str
    external_content: str
    attack_objective: str
    concealment_objective: Optional[str] = None
    expected_harmful_action: ToolCall
    agent_identity: Identity
    privileged_identity: Optional[Identity] = None
    controls: ControlRequirements = Field(default_factory=ControlRequirements)
    labels: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class DetectionSignals(BaseModel):
    prompt_injection: bool = False
    concealment: bool = False
    unauthorized_action: bool = False
    privilege_escalation: bool = False
    data_exfiltration: bool = False
    rag_poisoning: bool = False
    backdoor_risk: bool = False
    hallucination_risk: bool = False


class EvaluationResult(BaseModel):
    scenario_id: str
    passed: bool
    risk_level: str
    triggered_rules: List[str] = Field(default_factory=list)
    signals: DetectionSignals
    controls: Dict[str, Any] = Field(default_factory=dict)
    mappings: Dict[str, List[Dict[str, str]]] = Field(default_factory=dict)
    executed_action: ToolCall
    rationale: str
