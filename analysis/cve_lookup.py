"""
CVE Lookup - queries NVD API for CVEs related to detected technologies
"""

import requests
import time
from typing import List, Dict


NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def lookup_cves(technology: str, version: str = None, max_results: int = 5) -> List[Dict]:
    """
    Query NVD for CVEs matching a technology + optional version.
    Returns list of dicts with id, description, cvss_score, published.
    """
    query = technology
    if version:
        query = f"{technology} {version}"

    params = {
        "keywordSearch": query,
        "resultsPerPage": max_results,
        "keywordExactMatch": False,
    }

    try:
        r = requests.get(NVD_API, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
    except Exception:
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description (English)
        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # CVSS score (try v3.1 first, then v3.0, then v2)
        score = None
        severity = None
        metrics = cve.get("metrics", {})
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss_data = metrics[key][0].get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or metrics[key][0].get("baseSeverity")
                break

        published = cve.get("published", "")[:10]

        results.append({
            "id": cve_id,
            "description": desc[:300],
            "cvss_score": score,
            "severity": severity,
            "published": published,
        })

    return results


def enrich_findings_with_cves(findings: list) -> list:
    """
    Takes a list of Finding objects, looks up CVEs for any that
    mention specific technologies, enriches cves_or_techniques in place.
    Returns list of (finding, new_cves) tuples for reporting.
    """
    enriched = []

    for finding in findings:
        if finding.category not in ("tech_stack", "attack_surface", "exposed_assets"):
            continue

        # Extract tech + version hints from title/description
        # e.g. "Apache 2.4.49", "Jenkins 2.3", "PHP 7.2"
        tech_hints = _extract_tech_hints(finding.title + " " + finding.description)
        if not tech_hints:
            continue

        new_cves = []
        for tech, version in tech_hints:
            cves = lookup_cves(tech, version, max_results=3)
            time.sleep(0.6)  # NVD rate limit: ~5 req/30s without API key

            for c in cves:
                cve_tag = f"{c['id']} (CVSS {c['cvss_score']}, {c['severity']})" if c['cvss_score'] else c['id']
                if c['id'] not in finding.cves_or_techniques:
                    finding.cves_or_techniques.append(c['id'])
                    new_cves.append(c)

        if new_cves:
            enriched.append((finding, new_cves))

    return enriched


def _extract_tech_hints(text: str) -> List[tuple]:
    """
    Naive extraction of (technology, version) pairs from text.
    Looks for patterns like "Apache 2.4", "PHP 7.2.1", "nginx 1.18".
    """
    import re

    # Common tech keywords to look for
    techs = [
        "Apache", "nginx", "Nginx", "PHP", "WordPress", "Drupal", "Joomla",
        "Jenkins", "Tomcat", "IIS", "OpenSSL", "jQuery", "React", "Angular",
        "Django", "Rails", "Laravel", "Spring", "Struts", "Elasticsearch",
        "Redis", "MySQL", "PostgreSQL", "MongoDB", "Docker", "Kubernetes",
        "Gitlab", "Jira", "Confluence", "Grafana", "Prometheus",
    ]

    results = []
    for tech in techs:
        # Match tech name followed by optional version number
        pattern = rf"\b{re.escape(tech)}\s+([\d]+\.[\d]+(?:\.[\d]+)?)\b"
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            results.append((tech, match.group(1)))
        elif re.search(rf"\b{re.escape(tech)}\b", text, re.IGNORECASE):
            results.append((tech, None))

    # Deduplicate
    seen = set()
    deduped = []
    for t, v in results:
        key = t.lower()
        if key not in seen:
            seen.add(key)
            deduped.append((t, v))

    return deduped[:5]  # limit to 5 per finding
