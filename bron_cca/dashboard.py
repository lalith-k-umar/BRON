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
    best_capec_html = ""
    if isinstance(results, dict) and "highest_rewarding_capec" in results:
        capec_info = results["highest_rewarding_capec"]
        cid = escape(str(capec_info.get("id", "Unknown")))
        creward = capec_info.get("reward")
        reward_str = f"{creward:.3f}" if creward is not None else "N/A"
        artifacts = capec_info.get("linked_artifacts", {})
        capec_meta = artifacts.get("capec", {})
        cname = escape(str(capec_meta.get("name", "")))
        cdesc = escape(str(capec_meta.get("description", "")))

        # CWE Table
        cwes = artifacts.get("cwes", [])
        if cwes:
            cwe_rows = "".join(
                f"<tr><td><strong>{escape(str(item.get('id') or item.get('original_id') or ''))}</strong></td>"
                f"<td>{escape(str(item.get('name') or ''))}</td>"
                f"<td>{escape(str(item.get('description') or ''))}</td></tr>"
                for item in cwes
            )
            cwe_table = f"<table><thead><tr><th>CWE ID</th><th>Name</th><th>Description</th></tr></thead><tbody>{cwe_rows}</tbody></table>"
        else:
            cwe_table = "<p class='note'>No linked CWEs found in BRON.</p>"

        # CVE Table
        cves = artifacts.get("cves", [])
        if cves:
            sorted_cves = sorted(
                cves, key=lambda c: (0 if c.get("in_network") else 1, -float(c.get("cvss") or 0.0))
            )
            cve_rows = "".join(
                f"<tr{' class=\"active-net\"' if item.get('in_network') else ''}>"
                f"<td><strong>{escape(str(item.get('id') or item.get('original_id') or ''))}</strong></td>"
                f"<td>{float(item.get('cvss') or 0.0):.1f}</td>"
                f"<td>{'<span class=\"badge active\">Active</span>' if item.get('in_network') else '<span class=\"badge\">No</span>'}</td>"
                f"<td>{escape(str(item.get('via_cwe') or ''))}</td>"
                f"<td>{escape(str(item.get('description') or ''))}</td></tr>"
                for item in sorted_cves
            )
            cve_table = (
                "<table><thead><tr><th>CVE ID</th><th>CVSS</th><th>In Network</th><th>Via CWE</th><th>Description</th></tr></thead>"
                f"<tbody>{cve_rows}</tbody></table>"
            )
        else:
            cve_table = "<p class='note'>No linked CVEs found in BRON.</p>"

        # D3FEND Table
        d3fend = artifacts.get("d3fend", [])
        if d3fend:
            d3_rows = "".join(
                f"<tr><td><strong>{escape(str(item.get('id') or item.get('key') or ''))}</strong></td>"
                f"<td>{escape(str(item.get('name') or ''))}</td>"
                f"<td>{escape(str(item.get('via_technique') or ''))}"
                f"{(' (' + escape(str(item.get('technique_name'))) + ')') if item.get('technique_name') else ''}</td>"
                f"<td>{escape(str(item.get('description') or ''))}</td></tr>"
                for item in d3fend
            )
            d3_table = (
                "<table><thead><tr><th>D3FEND ID</th><th>Mitigation Name</th><th>Via ATT&amp;CK Technique</th><th>Description</th></tr></thead>"
                f"<tbody>{d3_rows}</tbody></table>"
            )
        else:
            d3_table = "<p class='note'>No linked D3FEND mitigations found in BRON.</p>"

        best_capec_html = f"""
        <div class="card">
            <h2>Highest Rewarding CAPEC Technique: {cid}</h2>
            <p><strong>Name:</strong> {cname} | <strong>Attack Reward:</strong> {reward_str}</p>
            {f'<p><strong>Description:</strong> {cdesc}</p>' if cdesc else ''}
            <h3>Linked CWE (Weaknesses) &mdash; {len(cwes)}</h3>
            {cwe_table}
            <h3>Linked CVE (Vulnerabilities) &mdash; {len(cves)}</h3>
            {cve_table}
            <h3>Linked D3FEND (Defensive Mitigations) &mdash; {len(d3fend)}</h3>
            {d3_table}
        </div>
        """

    plot = figure.to_html(full_html=False, include_plotlyjs=True)
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>CCA Dashboard</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#222;background:#fafafa}}
table{{border-collapse:collapse;margin:1rem 0 2rem;width:100%}}
th,td{{border:1px solid #ddd;padding:.5rem;text-align:left;font-size:0.9rem}}
th{{background:#f0f2f5}}
h1{{margin-bottom:0}} .note{{color:#666;font-style:italic}}
.card{{background:#fff;border:1px solid #e1e4e8;border-radius:6px;padding:1.5rem;margin:2rem 0;box-shadow:0 1px 3px rgba(0,0,0,0.05)}}
.badge{{display:inline-block;padding:0.2rem 0.5rem;border-radius:4px;font-size:0.8rem;background:#eee;color:#555}}
.badge.active{{background:#d4edda;color:#155724;font-weight:bold}}
tr.active-net{{background:#f8fff9}}
</style></head><body>
<h1>Competitive Coevolution Analysis</h1>
<p class="note">Use the run selector to compare reward trajectories. Residual values are asynchronous diagnostics, not synchronized payoffs.</p>
{plot}
{best_capec_html}
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