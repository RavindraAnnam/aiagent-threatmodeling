from agent_threatlab.engine import ThreatLabEngine
from agent_threatlab.scenario_loader import ScenarioLoader


def test_urgent_email_high_risk():
    scenario = ScenarioLoader.load("scenarios/urgent_email_concealment.yaml")
    result = ThreatLabEngine().run(scenario)
    assert result.risk_level in {"high", "critical"}
    assert result.signals.prompt_injection is True


def test_suite_scenario_has_reports_fields():
    scenario = ScenarioLoader.load("scenarios/rag_poisoned_knowledgebase.yaml")
    result = ThreatLabEngine().run(scenario)
    assert result.scenario_id == "rag_poisoned_knowledgebase"
    assert isinstance(result.controls, dict)
