from __future__ import annotations

from pathlib import Path
import yaml

from .models import Scenario


class ScenarioLoader:
    @staticmethod
    def load(path: str | Path) -> Scenario:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
        return Scenario.model_validate(raw)

    @staticmethod
    def load_dir(path: str | Path) -> list[Scenario]:
        p = Path(path)
        scenarios = []
        for file in sorted(p.glob("*.yaml")):
            scenarios.append(ScenarioLoader.load(file))
        return scenarios
