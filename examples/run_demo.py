from agent_threatlab.engine import ThreatLabEngine
from agent_threatlab.scenario_loader import ScenarioLoader

for path in [
    "scenarios/urgent_email_concealment.yaml",
    "scenarios/rag_poisoned_knowledgebase.yaml",
    "scenarios/multi_agent_escalation.yaml",
    "scenarios/code_backdoor_pull_request.yaml",
]:
    scenario = ScenarioLoader.load(path)
    result = ThreatLabEngine().run(scenario)
    print(f"{result.scenario_id}: passed={result.passed}, risk={result.risk_level}, action={result.executed_action.name}")
