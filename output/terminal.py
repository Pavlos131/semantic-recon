"""
Terminal Report - Rich-formatted output for the terminal
"""

import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.rule import Rule
from rich import box
from rich.columns import Columns
from rich.progress import Progress


CONFIDENCE_COLORS = {
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "dim cyan"
}

CONFIDENCE_ICONS = {
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🔵"
}

CATEGORY_ICONS = {
    "tech_stack": "⚙️ ",
    "internal_tools": "🔧",
    "employee_intel": "👤",
    "security_posture": "🛡️ ",
    "attack_surface": "🎯",
    "exposed_assets": "📂",
    "temporal_insights": "🕐",
}

BANNER = r"""
 ____                            _   _        ____
/ ___|  ___ _ __ ___   __ _ ___| |_(_) ___  |  _ \ ___  ___ ___  _ __
\___ \ / _ \ '_ ` _ \ / _` / __| __| |/ __| | |_) / _ \/ __/ _ \| '_ \
 ___) |  __/ | | | | | (_| \__ \ |_| | (__  |  _ <  __/ (_| (_) | | | |
|____/ \___|_| |_| |_|\__,_|___/\__|_|\___| |_| \_\___|\___\___/|_| |_|

 _____             _
| ____|_ __   __ _(_)_ __   ___
|  _| | '_ \ / _` | | '_ \ / _ \
| |___| | | | (_| | | | | |  __/
|_____|_| |_|\__, |_|_| |_|\___|
             |___/
"""


class TerminalReport:
    def __init__(self, target: str, domain: str, verbose: bool = False):
        self.target = target
        self.domain = domain
        self.verbose = verbose
        self.console = Console()

    def print_banner(self):
        self.console.print(f"[bold cyan]{BANNER}[/bold cyan]")
        self.console.print(Rule(style="cyan"))
        self.console.print(f"[bold]Target:[/bold] [cyan]{self.target}[/cyan]  |  [bold]Domain:[/bold] [cyan]{self.domain}[/cyan]  |  [bold]Time:[/bold] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.console.print(Rule(style="cyan"))
        self.console.print()

    def status(self, msg: str):
        self.console.print(f"[bold blue]▶[/bold blue] {msg}")

    def source_done(self, source: str, count: int):
        self.console.print(f"  [green]✓[/green] {source}: [bold]{count}[/bold] data points collected")

    def error(self, msg: str):
        self.console.print(f"[bold red]✗ ERROR:[/bold red] {msg}")

    def _print_finding(self, finding, index: int):
        conf_color = CONFIDENCE_COLORS.get(finding.confidence, "white")
        conf_icon = CONFIDENCE_ICONS.get(finding.confidence, "⚪")

        # Header
        source_badge = ""
        sc = getattr(finding, "source_count", 1)
        if sc >= 2:
            source_badge = f"  [dim](×{sc} sources)[/dim]"
        self.console.print(f"\n  [{index}] [bold]{finding.title}[/bold]  {conf_icon} [{conf_color}]{finding.confidence}[/{conf_color}]{source_badge}")

        # Description
        self.console.print(f"      [white]{finding.description}[/white]")

        # Inference chain
        if finding.inference_chain:
            self.console.print(f"      [dim]💭 Inference: {finding.inference_chain}[/dim]")

        # Attack relevance
        if finding.attack_relevance:
            self.console.print(f"      [yellow]⚡ Attack relevance: {finding.attack_relevance}[/yellow]")

        # CVEs/Techniques
        if finding.cves_or_techniques:
            tags = " ".join(f"[bold red]{t}[/bold red]" for t in finding.cves_or_techniques)
            self.console.print(f"      🔓 {tags}")

        # Sources
        if finding.evidence_sources and self.verbose:
            sources = ", ".join(finding.evidence_sources)
            self.console.print(f"      [dim]📎 Sources: {sources}[/dim]")

    def _print_section(self, title: str, icon: str, findings: list):
        if not findings:
            return

        self.console.print()
        self.console.print(Rule(f"[bold white]{icon} {title}[/bold white]", style="bold blue"))

        for i, finding in enumerate(findings, 1):
            self._print_finding(finding, i)

    def _print_maturity_bar(self, score: int):
        bar_length = 30
        filled = int((score / 10) * bar_length)
        empty = bar_length - filled

        if score <= 3:
            color = "red"
            label = "LOW MATURITY - Easy target"
        elif score <= 6:
            color = "yellow"
            label = "MEDIUM MATURITY - Some defenses"
        else:
            color = "green"
            label = "HIGH MATURITY - Hardened target"

        bar = f"[{color}]{'█' * filled}[/{color}][dim]{'░' * empty}[/dim]"
        self.console.print(f"\n  Security Maturity: {bar} [bold]{score}/10[/bold] — [{color}]{label}[/{color}]")

    def print_findings(self, report):
        self.console.print()
        self.console.print(Rule("[bold cyan]═══ SEMANTIC RECON REPORT ═══[/bold cyan]", style="cyan"))

        # Summary panel
        self.console.print()
        self.console.print(Panel(
            f"[bold white]{report.summary}[/bold white]",
            title="[bold cyan]Executive Summary[/bold cyan]",
            border_style="cyan"
        ))

        self._print_maturity_bar(report.security_maturity_score)

        # Stats
        total_findings = sum([
            len(report.tech_stack), len(report.internal_tools),
            len(report.employee_intel), len(report.security_posture),
            len(report.attack_surface), len(report.exposed_assets),
            len(report.temporal_insights)
        ])

        high = sum(1 for cat in [report.tech_stack, report.internal_tools, report.employee_intel,
                                  report.security_posture, report.attack_surface,
                                  report.exposed_assets, report.temporal_insights]
                   for f in cat if f.confidence == "HIGH")

        all_findings = [f for cat in [report.tech_stack, report.internal_tools, report.employee_intel,
                                       report.security_posture, report.attack_surface,
                                       report.exposed_assets, report.temporal_insights] for f in cat]
        cve_count = sum(1 for f in all_findings for c in f.cves_or_techniques if c.upper().startswith("CVE-"))

        self.console.print(f"\n  📊 Total findings: [bold]{total_findings}[/bold]  |  🔴 High confidence: [bold red]{high}[/bold red]  |  🔓 CVEs: [bold red]{cve_count}[/bold red]")

        # Print each section
        self._print_section("Attack Surface", "🎯", report.attack_surface)
        self._print_section("Exposed Assets", "📂", report.exposed_assets)
        self._print_section("Technology Stack", "⚙️", report.tech_stack)
        self._print_section("Internal Tools", "🔧", report.internal_tools)
        self._print_section("Employee Intelligence", "👤", report.employee_intel)
        self._print_section("Security Posture", "🛡️", report.security_posture)
        self._print_section("Temporal Insights", "🕐", report.temporal_insights)

        self.console.print()
        self.console.print(Rule(style="cyan"))
        self.console.print("[dim]Generated by Semantic Recon Engine | For authorized use only[/dim]")

    def print_diff(self, diff):
        """Print a DiffReport showing what changed between two runs."""
        self.console.print()
        self.console.print(Rule("[bold cyan]═══ DIFF REPORT ═══[/bold cyan]", style="cyan"))
        self.console.print(f"\n  Comparing against: [dim]{diff.previous_file}[/dim]")

        score_color = "green" if diff.score_after >= diff.score_before else "red"
        score_arrow = "↑" if diff.score_after > diff.score_before else ("↓" if diff.score_after < diff.score_before else "=")
        self.console.print(
            f"  Security maturity: [bold]{diff.score_before}/10[/bold] → "
            f"[bold {score_color}]{diff.score_after}/10 {score_arrow}[/bold {score_color}]"
        )

        total_new = len(diff.new_findings)
        total_removed = len(diff.removed_findings)
        total_changed = len(diff.changed_findings)
        self.console.print(
            f"\n  [bold green]+{total_new} new[/bold green]  |  "
            f"[bold red]-{total_removed} removed[/bold red]  |  "
            f"[bold yellow]~{total_changed} changed[/bold yellow]"
        )

        if diff.new_findings:
            self.console.print()
            self.console.print(Rule("[bold green]+ NEW FINDINGS[/bold green]", style="green"))
            for f in diff.new_findings:
                conf_color = CONFIDENCE_COLORS.get(f.confidence, "white")
                conf_icon = CONFIDENCE_ICONS.get(f.confidence, "⚪")
                cat_icon = CATEGORY_ICONS.get(f.category, "•")
                self.console.print(
                    f"  [bold green]+[/bold green] {cat_icon} [bold]{f.title}[/bold]  "
                    f"{conf_icon} [{conf_color}]{f.confidence}[/{conf_color}]"
                )

        if diff.removed_findings:
            self.console.print()
            self.console.print(Rule("[bold red]- REMOVED FINDINGS[/bold red]", style="red"))
            for f in diff.removed_findings:
                cat_icon = CATEGORY_ICONS.get(f.category, "•")
                self.console.print(f"  [bold red]-[/bold red] {cat_icon} [dim]{f.title}[/dim]")

        if diff.changed_findings:
            self.console.print()
            self.console.print(Rule("[bold yellow]~ CHANGED CONFIDENCE[/bold yellow]", style="yellow"))
            for f in diff.changed_findings:
                cat_icon = CATEGORY_ICONS.get(f.category, "•")
                arrow_color = "green" if f.status == "upgraded" else "red"
                self.console.print(
                    f"  [bold yellow]~[/bold yellow] {cat_icon} [bold]{f.title}[/bold]  "
                    f"[{arrow_color}]{f.detail}[/{arrow_color}]"
                )

        self.console.print()
        self.console.print(Rule(style="cyan"))

    def save_to_file(self, report, filepath: str):
        """Save report as JSON"""
        def finding_to_dict(f):
            return {
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "confidence": f.confidence,
                "inference_chain": f.inference_chain,
                "evidence_sources": f.evidence_sources,
                "attack_relevance": f.attack_relevance,
                "cves_or_techniques": f.cves_or_techniques,
                "source_count": getattr(f, "source_count", 1),
            }

        data = {
            "target": report.target,
            "domain": report.domain,
            "generated_at": datetime.now().isoformat(),
            "summary": report.summary,
            "security_maturity_score": report.security_maturity_score,
            "tech_stack": [finding_to_dict(f) for f in report.tech_stack],
            "internal_tools": [finding_to_dict(f) for f in report.internal_tools],
            "employee_intel": [finding_to_dict(f) for f in report.employee_intel],
            "security_posture": [finding_to_dict(f) for f in report.security_posture],
            "attack_surface": [finding_to_dict(f) for f in report.attack_surface],
            "exposed_assets": [finding_to_dict(f) for f in report.exposed_assets],
            "temporal_insights": [finding_to_dict(f) for f in report.temporal_insights]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
