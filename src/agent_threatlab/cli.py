from __future__ import annotations

import argparse
from pathlib import Path
from rich.console import Console
from rich.table import Table

from .engine import ThreatLabEngine
from .dashboard import generate_dashboard_from_scenarios
from .reporting import write_json, write_markdown
from .scenario_loader import ScenarioLoader

console = Console()


def cmd_run(path: str) -> int:
    engine = ThreatLabEngine()
    scenario = ScenarioLoader.load(path)
    result = engine.run(scenario)

    outdir = Path("reports") / result.scenario_id
    write_json(result, outdir / "result.json")
    write_markdown(result, outdir / "result.md")

    console.print(f"[bold]Scenario:[/bold] {result.scenario_id}")
    console.print(f"[bold]Passed:[/bold] {result.passed}")
    console.print(f"[bold]Risk:[/bold] {result.risk_level}")
    console.print(f"[bold]Rules:[/bold] {', '.join(result.triggered_rules) or 'none'}")
    console.print(f"[bold]Reports:[/bold] {outdir}")
    return 0


def cmd_run_suite(path: str) -> int:
    engine = ThreatLabEngine()
    scenarios = ScenarioLoader.load_dir(path)
    table = Table(title="Agent ThreatLab Suite Results")
    table.add_column("Scenario")
    table.add_column("Passed")
    table.add_column("Risk")
    table.add_column("Action")

    for scenario in scenarios:
        result = engine.run(scenario)
        outdir = Path("reports") / result.scenario_id
        write_json(result, outdir / "result.json")
        write_markdown(result, outdir / "result.md")
        table.add_row(result.scenario_id, str(result.passed), result.risk_level, result.executed_action.name)

    console.print(table)
    console.print("[bold]Reports written to:[/bold] reports/")
    return 0


def cmd_dashboard(path: str, outdir: str = "dashboard") -> int:
    index_path = generate_dashboard_from_scenarios(path, outdir=outdir)
    console.print(f"[bold]Dashboard:[/bold] {index_path}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Agent ThreatLab CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    run_p = sub.add_parser("run", help="Run a single scenario")
    run_p.add_argument("path")

    suite_p = sub.add_parser("run-suite", help="Run all scenarios in a directory")
    suite_p.add_argument("path")

    dash_p = sub.add_parser("dashboard", help="Generate a small web dashboard from scenarios")
    dash_p.add_argument("path")
    dash_p.add_argument("--outdir", default="dashboard")

    args = parser.parse_args()

    if args.command == "run":
        return cmd_run(args.path)
    if args.command == "run-suite":
        return cmd_run_suite(args.path)
    if args.command == "dashboard":
        return cmd_dashboard(args.path, outdir=args.outdir)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
