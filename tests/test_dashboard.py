from pathlib import Path

from agent_threatlab.dashboard import generate_dashboard_from_scenarios
from agent_threatlab.engine import ThreatLabEngine
from agent_threatlab.scenario_loader import ScenarioLoader


def test_engine_adds_mappings() -> None:
    scenario = ScenarioLoader.load('scenarios/urgent_email_concealment.yaml')
    result = ThreatLabEngine().run(scenario)
    assert 'stride' in result.mappings
    assert 'pasta' in result.mappings
    assert 'mitre_atlas' in result.mappings
    assert any(item['category'] == 'Tampering' for item in result.mappings['stride'])


def test_dashboard_generation(tmp_path: Path) -> None:
    index_path = generate_dashboard_from_scenarios('scenarios', outdir=tmp_path)
    assert index_path.exists()
    text = index_path.read_text(encoding='utf-8')
    assert 'Agent ThreatLab Dashboard' in text
    assert 'MITRE ATLAS' in text
