"""
HTML Report - generates an interactive HTML report with D3.js knowledge graph
and MITRE ATT&CK heatmap.
"""

import json
import os
from datetime import datetime


CONFIDENCE_COLORS = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#3b82f6"}

CATEGORY_ICONS = {
    "tech_stack": "⚙️",
    "internal_tools": "🔧",
    "employee_intel": "👤",
    "security_posture": "🛡️",
    "attack_surface": "🎯",
    "exposed_assets": "📂",
    "temporal_insights": "🕐",
}

NODE_COLORS = {
    "technology": "#6366f1",
    "service": "#8b5cf6",
    "person": "#ec4899",
    "endpoint": "#f97316",
    "attack_vector": "#ef4444",
    "vulnerability": "#dc2626",
    "unknown": "#6b7280",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Semantic Recon — {target} ({domain})</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', monospace; }}
  header {{ background: #1e293b; padding: 20px 40px; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }}
  header h1 {{ color: #38bdf8; font-size: 1.4rem; }}
  header span {{ color: #94a3b8; font-size: 0.85rem; }}
  .tabs {{ display: flex; background: #1e293b; border-bottom: 1px solid #334155; }}
  .tab {{ padding: 12px 28px; cursor: pointer; color: #94a3b8; border-bottom: 2px solid transparent; font-size: 0.9rem; }}
  .tab.active {{ color: #38bdf8; border-bottom-color: #38bdf8; }}
  .tab-content {{ display: none; padding: 24px 40px; }}
  .tab-content.active {{ display: block; }}
  .summary-box {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  .summary-box p {{ color: #cbd5e1; line-height: 1.6; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 20px; flex-wrap: wrap; }}
  .stat {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px 24px; text-align: center; min-width: 120px; }}
  .stat .num {{ font-size: 2rem; font-weight: bold; color: #38bdf8; }}
  .stat .lbl {{ font-size: 0.75rem; color: #94a3b8; margin-top: 4px; }}
  .maturity-bar {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px 24px; margin-bottom: 20px; }}
  .maturity-bar label {{ font-size: 0.8rem; color: #94a3b8; }}
  .bar-outer {{ background: #334155; border-radius: 4px; height: 12px; margin-top: 8px; }}
  .bar-inner {{ height: 12px; border-radius: 4px; transition: width 0.5s; }}
  .section {{ margin-bottom: 24px; }}
  .section h2 {{ font-size: 1rem; color: #94a3b8; margin-bottom: 12px; border-bottom: 1px solid #1e293b; padding-bottom: 6px; }}
  .finding {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 10px; }}
  .finding-header {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; }}
  .finding-title {{ font-weight: bold; color: #e2e8f0; }}
  .badge {{ font-size: 0.7rem; padding: 2px 8px; border-radius: 999px; font-weight: bold; }}
  .badge-HIGH {{ background: #7f1d1d; color: #fca5a5; }}
  .badge-MEDIUM {{ background: #78350f; color: #fde68a; }}
  .badge-LOW {{ background: #1e3a5f; color: #93c5fd; }}
  .finding p {{ font-size: 0.85rem; color: #94a3b8; margin-bottom: 6px; line-height: 1.5; }}
  .inference {{ font-size: 0.8rem; color: #64748b; font-style: italic; }}
  .attack {{ font-size: 0.8rem; color: #fbbf24; }}
  .cves {{ display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }}
  .cve-tag {{ background: #450a0a; color: #fca5a5; font-size: 0.7rem; padding: 2px 8px; border-radius: 4px; border: 1px solid #7f1d1d; }}
  #graph-container {{ width: 100%; height: 600px; background: #0f172a; border: 1px solid #334155; border-radius: 8px; overflow: hidden; position: relative; }}
  #graph-legend {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }}
  .legend-item {{ display: flex; align-items: center; gap: 6px; font-size: 0.75rem; color: #94a3b8; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; }}
  .attack-paths {{ margin-top: 16px; }}
  .path-item {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 14px; margin-bottom: 8px; }}
  .path-item .risk {{ font-size: 0.75rem; color: #f97316; float: right; }}
  .path-desc {{ font-size: 0.85rem; color: #cbd5e1; font-family: monospace; }}
  svg text {{ font-size: 11px; fill: #94a3b8; }}
</style>
</head>
<body>
<header>
  <h1>Semantic Recon Engine &mdash; <span style="color:#e2e8f0">{target}</span> <span style="color:#64748b">({domain})</span></h1>
  <span>Generated {generated_at} &nbsp;|&nbsp; For authorized use only</span>
</header>

<div class="tabs">
  <div class="tab active" onclick="showTab('overview')">Overview</div>
  <div class="tab" onclick="showTab('findings')">Findings</div>
  <div class="tab" onclick="showTab('graph')">Knowledge Graph</div>
  <div class="tab" onclick="showTab('paths')">Attack Paths</div>
</div>

<!-- OVERVIEW TAB -->
<div id="tab-overview" class="tab-content active">
  <div class="summary-box"><p>{summary}</p></div>
  <div class="stats">
    <div class="stat"><div class="num">{total_findings}</div><div class="lbl">Total Findings</div></div>
    <div class="stat"><div class="num" style="color:#ef4444">{high_count}</div><div class="lbl">High Confidence</div></div>
    <div class="stat"><div class="num" style="color:#f59e0b">{medium_count}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:#3b82f6">{low_count}</div><div class="lbl">Low</div></div>
    <div class="stat"><div class="num" style="color:#dc2626">{cve_count}</div><div class="lbl">CVEs Found</div></div>
  </div>
  <div class="maturity-bar">
    <label>Security Maturity Score: <strong style="color:#e2e8f0">{security_maturity_score}/10</strong></label>
    <div class="bar-outer"><div class="bar-inner" style="width:{maturity_pct}%; background:{maturity_color}"></div></div>
  </div>
</div>

<!-- FINDINGS TAB -->
<div id="tab-findings" class="tab-content">
{findings_html}
</div>

<!-- GRAPH TAB -->
<div id="tab-graph" class="tab-content">
  <div id="graph-legend">{legend_html}</div>
  <div id="graph-container"><svg id="graph-svg" width="100%" height="100%"></svg></div>
</div>

<!-- ATTACK PATHS TAB -->
<div id="tab-paths" class="tab-content">
  <div class="attack-paths">{paths_html}</div>
</div>

<script>
function showTab(name) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'graph') initGraph();
}}

// D3.js Force Graph
const graphData = {graph_data};
const nodeColors = {node_colors};
let graphInitialized = false;

function initGraph() {{
  if (graphInitialized || !graphData.nodes.length) return;
  graphInitialized = true;

  const container = document.getElementById('graph-container');
  const width = container.clientWidth;
  const height = container.clientHeight;
  const svg = d3.select('#graph-svg').attr('width', width).attr('height', height);

  const g = svg.append('g');

  svg.call(d3.zoom().scaleExtent([0.2, 4]).on('zoom', e => g.attr('transform', e.transform)));

  // Arrow marker
  svg.append('defs').append('marker')
    .attr('id', 'arrow').attr('viewBox', '0 -5 10 10')
    .attr('refX', 20).attr('refY', 0)
    .attr('markerWidth', 6).attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path').attr('d', 'M0,-5L10,0L0,5').attr('fill', '#475569');

  const simulation = d3.forceSimulation(graphData.nodes)
    .force('link', d3.forceLink(graphData.edges).id(d => d.id).distance(100))
    .force('charge', d3.forceManyBody().strength(-300))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide(30));

  const link = g.append('g').selectAll('line')
    .data(graphData.edges).enter().append('line')
    .attr('stroke', '#334155').attr('stroke-width', 1.5)
    .attr('marker-end', 'url(#arrow)');

  const linkLabel = g.append('g').selectAll('text')
    .data(graphData.edges).enter().append('text')
    .text(d => d.relation).attr('font-size', '9px').attr('fill', '#475569');

  const node = g.append('g').selectAll('g')
    .data(graphData.nodes).enter().append('g')
    .call(d3.drag()
      .on('start', (e, d) => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; }})
      .on('drag', (e, d) => {{ d.fx = e.x; d.fy = e.y; }})
      .on('end', (e, d) => {{ if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }}));

  node.append('circle')
    .attr('r', d => d.type === 'vulnerability' ? 8 : 14)
    .attr('fill', d => nodeColors[d.type] || nodeColors.unknown)
    .attr('stroke', '#1e293b').attr('stroke-width', 2);

  node.append('text')
    .text(d => d.label.length > 20 ? d.label.substring(0, 18) + '…' : d.label)
    .attr('text-anchor', 'middle').attr('dy', 26).attr('font-size', '10px');

  node.append('title').text(d => `${{d.label}} (${{d.type}})`);

  simulation.on('tick', () => {{
    link.attr('x1', d => d.source.x).attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    linkLabel.attr('x', d => (d.source.x + d.target.x) / 2)
             .attr('y', d => (d.source.y + d.target.y) / 2);
    node.attr('transform', d => `translate(${{d.x}},${{d.y}})`);
  }});
}}
</script>
</body>
</html>
"""


def _finding_html(finding) -> str:
    badge = f'<span class="badge badge-{finding.confidence}">{finding.confidence}</span>'
    cves = ""
    if finding.cves_or_techniques:
        tags = "".join(f'<span class="cve-tag">{c}</span>' for c in finding.cves_or_techniques)
        cves = f'<div class="cves">{tags}</div>'
    inference = f'<p class="inference">💭 {finding.inference_chain}</p>' if finding.inference_chain else ""
    attack = f'<p class="attack">⚡ {finding.attack_relevance}</p>' if finding.attack_relevance else ""
    return f"""
<div class="finding">
  <div class="finding-header">
    <span class="finding-title">{finding.title}</span>
    {badge}
  </div>
  <p>{finding.description}</p>
  {inference}
  {attack}
  {cves}
</div>"""


def _section_html(title: str, icon: str, findings: list) -> str:
    if not findings:
        return ""
    items = "".join(_finding_html(f) for f in findings)
    return f'<div class="section"><h2>{icon} {title}</h2>{items}</div>'


def generate_html_report(report, graph_data: dict = None, attack_paths: list = None) -> str:
    all_findings = (
        report.tech_stack + report.internal_tools + report.employee_intel +
        report.security_posture + report.attack_surface + report.exposed_assets +
        report.temporal_insights
    )
    total = len(all_findings)
    high = sum(1 for f in all_findings if f.confidence == "HIGH")
    medium = sum(1 for f in all_findings if f.confidence == "MEDIUM")
    low = sum(1 for f in all_findings if f.confidence == "LOW")
    cve_count = sum(len(f.cves_or_techniques) for f in all_findings)
    score = report.security_maturity_score
    maturity_pct = score * 10
    maturity_color = "#ef4444" if score <= 3 else "#f59e0b" if score <= 6 else "#22c55e"

    findings_html = (
        _section_html("Attack Surface", "🎯", report.attack_surface) +
        _section_html("Exposed Assets", "📂", report.exposed_assets) +
        _section_html("Technology Stack", "⚙️", report.tech_stack) +
        _section_html("Internal Tools", "🔧", report.internal_tools) +
        _section_html("Employee Intelligence", "👤", report.employee_intel) +
        _section_html("Security Posture", "🛡️", report.security_posture) +
        _section_html("Temporal Insights", "🕐", report.temporal_insights)
    )

    gdata = graph_data or {"nodes": [], "edges": []}
    legend_html = "".join(
        f'<div class="legend-item"><div class="legend-dot" style="background:{c}"></div>{t}</div>'
        for t, c in NODE_COLORS.items()
    )

    if attack_paths:
        paths_items = []
        for p in attack_paths:
            risk_pct = int(p.risk_score * 100)
            paths_items.append(
                f'<div class="path-item">'
                f'<span class="risk">Risk: {risk_pct}%</span>'
                f'<div class="path-desc">{p.description}</div>'
                f'</div>'
            )
        paths_html = "".join(paths_items)
    else:
        paths_html = '<p style="color:#64748b">No attack paths identified.</p>'

    return HTML_TEMPLATE.format(
        target=report.target,
        domain=report.domain,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        summary=report.summary or "No summary available.",
        total_findings=total,
        high_count=high,
        medium_count=medium,
        low_count=low,
        cve_count=cve_count,
        security_maturity_score=score,
        maturity_pct=maturity_pct,
        maturity_color=maturity_color,
        findings_html=findings_html,
        graph_data=json.dumps(gdata),
        node_colors=json.dumps(NODE_COLORS),
        legend_html=legend_html,
        paths_html=paths_html,
    )


def save_html_report(report, filepath: str, graph_data: dict = None, attack_paths: list = None):
    html = generate_html_report(report, graph_data=graph_data, attack_paths=attack_paths)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
