from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List

from .engine import ThreatLabEngine
from .scenario_loader import ScenarioLoader


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Agent ThreatLab Dashboard</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 0; background: #0b1020; color: #ecf1ff; }
    header { padding: 20px 24px; border-bottom: 1px solid #24304d; background: #111833; position: sticky; top: 0; }
    h1, h2, h3 { margin: 0 0 12px; }
    main { padding: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .card { background: #121a36; border: 1px solid #24304d; border-radius: 14px; padding: 16px; box-shadow: 0 8px 24px rgba(0,0,0,.18); }
    .muted { color: #9eb0d5; font-size: 14px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { border-bottom: 1px solid #24304d; padding: 10px 8px; text-align: left; vertical-align: top; }
    th { color: #b7c5e4; font-size: 13px; }
    .pill { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 12px; background: #223057; margin: 2px 4px 2px 0; }
    .risk-low { color: #96f1b0; }
    .risk-medium { color: #ffd46e; }
    .risk-high, .risk-critical { color: #ff8e8e; }
    details { margin-top: 12px; }
    summary { cursor: pointer; color: #d5e2ff; }
    code { background: #0c1430; padding: 2px 6px; border-radius: 6px; }
  </style>
</head>
<body>
<header>
  <h1>Agent ThreatLab Dashboard</h1>
  <div class="muted">Scenario analytics, risk posture, and STRIDE / PASTA / MITRE ATLAS views.</div>
</header>
<main>
  <section class="grid" id="summary"></section>
  <section class="card">
    <h2>Scenario Results</h2>
    <div class="muted">Each scenario includes controls, signals, and mapped threat-model views.</div>
    <div id="scenario-table"></div>
  </section>
  <section class="grid" style="margin-top: 24px;">
    <div class="card"><h2>STRIDE Distribution</h2><div id="stride"></div></div>
    <div class="card"><h2>PASTA Stages</h2><div id="pasta"></div></div>
    <div class="card"><h2>MITRE ATLAS Techniques</h2><div id="mitre"></div></div>
  </section>
</main>
<script>
const data = __DATA__;

function counter(items, key) {
  const counts = {};
  for (const item of items) {
    const value = item[key];
    counts[value] = (counts[value] || 0) + 1;
  }
  return counts;
}

function renderCountMap(map) {
  const rows = Object.entries(map).sort((a,b) => b[1]-a[1]);
  return rows.map(([k,v]) => `<div style="margin:6px 0"><strong>${k}</strong>: ${v}</div>`).join('');
}

const passed = data.results.filter(r => r.passed).length;
const critical = data.results.filter(r => r.risk_level === 'critical').length;
const high = data.results.filter(r => r.risk_level === 'high').length;
const summary = document.getElementById('summary');
summary.innerHTML = `
  <div class="card"><h3>${data.results.length}</h3><div class="muted">Scenarios</div></div>
  <div class="card"><h3>${passed}</h3><div class="muted">Passed</div></div>
  <div class="card"><h3>${high}</h3><div class="muted">High Risk</div></div>
  <div class="card"><h3>${critical}</h3><div class="muted">Critical Risk</div></div>
`;

function pill(text) { return `<span class="pill">${text}</span>` }

const table = document.getElementById('scenario-table');
const rows = data.results.map((r) => {
  const stride = r.mappings.stride.map(x => pill(x.category)).join('');
  const pasta = r.mappings.pasta.map(x => pill(x.stage)).join('');
  const mitre = r.mappings.mitre_atlas.map(x => pill(x.technique)).join('');
  const triggered = r.triggered_rules.map(pill).join('') || '<span class="muted">none</span>';
  return `<tr>
    <td><strong>${r.scenario_id}</strong><div class="muted">${r.title}</div></td>
    <td class="risk-${r.risk_level}"><strong>${r.risk_level}</strong></td>
    <td>${r.executed_action.name}</td>
    <td>${triggered}</td>
    <td>
      <details><summary>View mappings</summary>
        <div><strong>STRIDE</strong><br/>${stride}</div>
        <div style="margin-top:8px"><strong>PASTA</strong><br/>${pasta}</div>
        <div style="margin-top:8px"><strong>MITRE ATLAS</strong><br/>${mitre}</div>
      </details>
    </td>
  </tr>`;
}).join('');
table.innerHTML = `<table>
  <thead><tr><th>Scenario</th><th>Risk</th><th>Action</th><th>Rules</th><th>Mappings</th></tr></thead>
  <tbody>${rows}</tbody>
</table>`;

document.getElementById('stride').innerHTML = renderCountMap(data.summary.stride);
document.getElementById('pasta').innerHTML = renderCountMap(data.summary.pasta);
document.getElementById('mitre').innerHTML = renderCountMap(data.summary.mitre_atlas);
</script>
</body>
</html>
"""


def _build_dashboard_payload(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    stride_counter: Counter[str] = Counter()
    pasta_counter: Counter[str] = Counter()
    mitre_counter: Counter[str] = Counter()

    for result in results:
        for item in result["mappings"]["stride"]:
            stride_counter[item["category"]] += 1
        for item in result["mappings"]["pasta"]:
            pasta_counter[item["stage"]] += 1
        for item in result["mappings"]["mitre_atlas"]:
            mitre_counter[item["technique"]] += 1

    return {
        "results": results,
        "summary": {
            "stride": dict(stride_counter),
            "pasta": dict(pasta_counter),
            "mitre_atlas": dict(mitre_counter),
        },
    }


def generate_dashboard_from_scenarios(scenarios_dir: str | Path, outdir: str | Path = "dashboard") -> Path:
    engine = ThreatLabEngine()
    scenarios = ScenarioLoader.load_dir(scenarios_dir)
    results = []
    for scenario in scenarios:
        result = engine.run(scenario)
        payload = result.model_dump()
        payload["title"] = scenario.title
        results.append(payload)

    dashboard = _build_dashboard_payload(results)
    out_path = Path(outdir)
    out_path.mkdir(parents=True, exist_ok=True)
    with open(out_path / "dashboard.json", "w", encoding="utf-8") as f:
        json.dump(dashboard, f, indent=2)

    html_content = DASHBOARD_HTML.replace("__DATA__", json.dumps(dashboard))
    with open(out_path / "index.html", "w", encoding="utf-8") as f:
        f.write(html_content)
    return out_path / "index.html"


def serve_dashboard(path: str | Path, host: str = "127.0.0.1", port: int = 8000) -> None:
    root = Path(path).resolve().parent

    class Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(root), **kwargs)

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"Serving dashboard at http://{host}:{port}/{Path(path).name}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate or serve the Agent ThreatLab dashboard")
    parser.add_argument("scenarios", help="Directory containing YAML scenarios")
    parser.add_argument("--outdir", default="dashboard")
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args()

    index_path = generate_dashboard_from_scenarios(args.scenarios, args.outdir)
    print(f"Dashboard written to {index_path}")
    if args.serve:
        serve_dashboard(index_path, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
