"""Standalone HTML visualization for JSON-safe CCA experiment results."""

import argparse
import json
from html import escape
from pathlib import Path


def _runs(results):
    if isinstance(results, dict):
        results = results.get("runs", [])
    if not isinstance(results, list) or not results:
        raise ValueError("CCA results must contain a non-empty list of runs")
    return results


def build_dashboard_html(results):
    """Return an offline Plotly dashboard for results from run_experiment()."""
    try:
        import plotly.graph_objects as go
    except ImportError as exc:
        raise RuntimeError("Dashboard generation requires the 'plotly' package") from exc

    runs = _runs(results)
    figure = go.Figure()
    visibility = []
    for run_index, run in enumerate(runs):
        generations = list(range(len(run["attacker_reward"])))
        metrics = run.get("generation_metrics", [])
        figure.add_trace(
            go.Scatter(
                x=generations,
                y=run["attacker_reward"],
                name=f"Run {run.get('seed', run_index)} attacker",
                visible=run_index == 0,
            )
        )
        figure.add_trace(
            go.Scatter(
                x=generations,
                y=run["defender_reward"],
                name=f"Run {run.get('seed', run_index)} defender",
                visible=run_index == 0,
            )
        )
        figure.add_trace(
            go.Scatter(
                x=generations,
                y=[item["asynchronous_zero_sum_residual"] for item in metrics],
                name=f"Run {run.get('seed', run_index)} residual",
                visible=run_index == 0,
            )
        )
        visibility.extend([run_index == 0] * 3)

    buttons = []
    for run_index, run in enumerate(runs):
        visible = [False] * (len(runs) * 3)
        visible[run_index * 3 : run_index * 3 + 3] = [True] * 3
        buttons.append(
            {
                "label": f"Run {run.get('seed', run_index)}",
                "method": "update",
                "args": [{"visible": visible}],
            }
        )
    figure.update_layout(
        title="CCA reward and zero-sum diagnostics",
        xaxis_title="Generation",
        yaxis_title="Value",
        updatemenus=[{"buttons": buttons, "direction": "down", "x": 1, "xanchor": "right"}],
        annotations=[
            {
                "text": "Attacker is measured before attacker evolution; defender is measured after attacker evolution.",
                "showarrow": False,
                "xref": "paper",
                "x": 0,
                "y": 1.12,
            }
        ],
    )

    first_run = runs[0]
    attacker_rows = "".join(
        f"<tr><td>{escape(', '.join(record['actions']))}</td><td>{record['genes']}</td></tr>"
        for record in first_run.get("final_attacker_population", [])
    )
    defender_rows = "".join(
        f"<tr><td>{escape(', '.join(record['actions']))}</td><td>{record['genes']}</td></tr>"
        for record in first_run.get("final_defender_population", [])
    )
    plot = figure.to_html(full_html=False, include_plotlyjs=True)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>CCA Dashboard</title>
<style>body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;margin:1rem 0 2rem;min-width:28rem}}th,td{{border:1px solid #ccc;padding:.4rem;text-align:left}}
h1{{margin-bottom:0}} .note{{color:#555}}</style></head><body>
<h1>Competitive Coevolution Analysis</h1>
<p class="note">Use the run selector to compare reward trajectories. Residual values are asynchronous diagnostics, not synchronized payoffs.</p>
{plot}
<h2>Final attacker strategies (first run)</h2>
<table><thead><tr><th>CAPEC actions</th><th>Genes</th></tr></thead><tbody>{attacker_rows}</tbody></table>
<h2>Final defender strategies (first run)</h2>
<table><thead><tr><th>CPE patches</th><th>Genes</th></tr></thead><tbody>{defender_rows}</tbody></table>
</body></html>"""


def write_dashboard(results, output_path):
    output_path = Path(output_path)
    output_path.write_text(build_dashboard_html(results), encoding="utf-8")
    return output_path


def main():
    parser = argparse.ArgumentParser(description="Render a CCA result JSON as an offline HTML dashboard")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    results = json.loads(args.input.read_text(encoding="utf-8"))
    write_dashboard(results, args.output)


if __name__ == "__main__":
    main()