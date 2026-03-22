from __future__ import annotations

import json
from pathlib import Path
from .models import EvaluationResult


def write_json(result: EvaluationResult, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result.model_dump(), f, indent=2)


def write_markdown(result: EvaluationResult, path: str | Path) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Scenario Report: {result.scenario_id}",
        "",
        f"- Passed: **{result.passed}**",
        f"- Risk level: **{result.risk_level}**",
        f"- Executed action: `{result.executed_action.name}`",
        f"- Triggered rules: {', '.join(result.triggered_rules) or 'none'}",
        "",
        "## Signals",
        "",
    ]
    for k, v in result.signals.model_dump().items():
        lines.append(f"- {k}: **{v}**")
    lines.extend(["", "## Controls", ""])
    for k, v in result.controls.items():
        lines.append(f"- {k}: **{v}**")
    lines.extend(["", "## Threat Model Mappings", ""])
    for framework, items in result.mappings.items():
        lines.append(f"### {framework.replace('_', ' ').title()}")
        lines.append("")
        for item in items:
            details = ", ".join(f"{k}={v}" for k, v in item.items())
            lines.append(f"- {details}")
        lines.append("")

    lines.extend(["", "## Rationale", "", result.rationale, ""])

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
