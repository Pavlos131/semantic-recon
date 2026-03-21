"""
Diff Engine — compare two recon runs and surface what changed.
"""

import json
from dataclasses import dataclass, field
from typing import List


@dataclass
class DiffFinding:
    category: str
    title: str
    confidence: str
    status: str  # "new" | "removed" | "upgraded" | "downgraded"
    detail: str = ""  # e.g. "MEDIUM → HIGH"


@dataclass
class DiffReport:
    target: str
    domain: str
    previous_file: str
    new_findings: List[DiffFinding] = field(default_factory=list)
    removed_findings: List[DiffFinding] = field(default_factory=list)
    changed_findings: List[DiffFinding] = field(default_factory=list)
    score_before: int = 0
    score_after: int = 0


CATEGORIES = [
    "tech_stack", "internal_tools", "employee_intel",
    "security_posture", "attack_surface", "exposed_assets", "temporal_insights"
]


def load_json_report(filepath: str) -> dict:
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def _index_findings(report_dict: dict) -> dict:
    """Build title → {confidence, category} index from a JSON report dict."""
    index = {}
    for cat in CATEGORIES:
        for f in report_dict.get(cat, []):
            title = f.get("title", "").strip().lower()
            if title:
                index[title] = {
                    "confidence": f.get("confidence", "LOW"),
                    "category": cat,
                    "title": f.get("title", ""),
                }
    return index


def compute_diff(current_report, previous_dict: dict) -> DiffReport:
    """
    current_report: ReconReport dataclass (current run)
    previous_dict:  dict loaded from a previous JSON report file
    """
    diff = DiffReport(
        target=current_report.target,
        domain=current_report.domain,
        previous_file=previous_dict.get("_source_file", "previous report"),
        score_before=previous_dict.get("security_maturity_score", 0),
        score_after=current_report.security_maturity_score,
    )

    # Build previous index
    prev_index = _index_findings(previous_dict)

    # Build current index from dataclass
    curr_index = {}
    for cat in CATEGORIES:
        for f in getattr(current_report, cat, []):
            title = f.title.strip().lower()
            if title:
                curr_index[title] = {
                    "confidence": f.confidence,
                    "category": cat,
                    "title": f.title,
                }

    # New findings (in current but not in previous)
    for title_norm, info in curr_index.items():
        if title_norm not in prev_index:
            diff.new_findings.append(DiffFinding(
                category=info["category"],
                title=info["title"],
                confidence=info["confidence"],
                status="new",
            ))

    # Removed findings (in previous but not in current)
    for title_norm, info in prev_index.items():
        if title_norm not in curr_index:
            diff.removed_findings.append(DiffFinding(
                category=info["category"],
                title=info["title"],
                confidence=info["confidence"],
                status="removed",
            ))

    # Changed confidence
    CONF_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for title_norm, curr_info in curr_index.items():
        if title_norm in prev_index:
            prev_conf = prev_index[title_norm]["confidence"]
            curr_conf = curr_info["confidence"]
            if prev_conf != curr_conf:
                prev_rank = CONF_RANK.get(prev_conf, 1)
                curr_rank = CONF_RANK.get(curr_conf, 1)
                status = "upgraded" if curr_rank > prev_rank else "downgraded"
                diff.changed_findings.append(DiffFinding(
                    category=curr_info["category"],
                    title=curr_info["title"],
                    confidence=curr_conf,
                    status=status,
                    detail=f"{prev_conf} → {curr_conf}",
                ))

    return diff
