#!/usr/bin/env python3
"""
Semantic Recon Engine
"""

import argparse
import sys
import json
import os
from output.terminal import TerminalReport
from collectors.github_collector import GitHubCollector
from collectors.google_collector import GoogleDorksCollector
from collectors.wayback_collector import WaybackCollector
from collectors.linkedin_collector import LinkedInCollector
from collectors.dns_collector import DNSCollector
from collectors.shodan_collector import ShodanCollector
from collectors.github_secrets_collector import GitHubSecretsCollector
from collectors.stackoverflow_collector import StackOverflowCollector
from analysis.semantic_engine import SemanticEngine

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def load_config(path: str) -> dict:
    if not HAS_YAML:
        print("PyYAML not installed. Run: pip install pyyaml")
        sys.exit(1)
    with open(path) as f:
        return yaml.safe_load(f)


def main():
    parser = argparse.ArgumentParser(
        description="Semantic Recon Engine - LLM-powered OSINT tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py --target "Tesla" --domain tesla.com
  python recon.py --config config.yaml
  python recon.py --target "ACME" --domain acme.com --sources github wayback google
  python recon.py --target "ACME" --domain acme.com --resume .recon_cache_acme.com.json
        """
    )
    parser.add_argument("--config", default=None, help="Path to YAML config file")
    parser.add_argument("--target", default=None, help="Company/organization name")
    parser.add_argument("--domain", default=None, help="Target domain (e.g. tesla.com)")
    parser.add_argument("--github-token", default=None, help="GitHub API token")
    parser.add_argument("--anthropic-key", default=None, help="Anthropic API key")
    parser.add_argument(
        "--sources",
        nargs="+",
        choices=["github", "google", "wayback", "linkedin", "dns", "shodan", "github_secrets", "stackoverflow"],
        default=None,
        help="Data sources to use"
    )
    parser.add_argument("--shodan-key", default=None, help="Shodan API key")
    parser.add_argument("--output", default=None, help="Save JSON report to file")
    parser.add_argument("--html", default=None, help="Save HTML report to file (e.g. report.html)")
    parser.add_argument("--verbose", action="store_true", help="Show raw collected data")
    parser.add_argument("--llm", choices=["anthropic", "ollama"], default=None,
                        help="LLM backend to use")
    parser.add_argument("--ollama-model", default=None, help="Ollama model name")
    parser.add_argument("--ollama-url", default=None, help="Ollama server URL")
    parser.add_argument("--resume", default=None, metavar="FILE",
                        help="Skip collection, load raw data from a cache file")
    parser.add_argument("--no-cve", action="store_true", help="Skip CVE auto-lookup")
    parser.add_argument("--no-cache", action="store_true", help="Ignore collector cache")

    args = parser.parse_args()

    # Load config file if provided
    cfg = {}
    if args.config:
        cfg = load_config(args.config)

    # Resolve values: CLI args override config, config overrides defaults
    target = args.target or cfg.get("target")
    domain = args.domain or cfg.get("domain")

    if not target or not domain:
        parser.error("--target and --domain are required (or set them in config.yaml)")

    llm_cfg = cfg.get("llm", {})
    llm = args.llm or llm_cfg.get("provider", "anthropic")
    ollama_model = args.ollama_model or llm_cfg.get("ollama_model", "llama3")
    ollama_url = args.ollama_url or llm_cfg.get("ollama_url", "http://localhost:11434")

    src_cfg = cfg.get("sources", {})
    if args.sources:
        active_sources = args.sources
    else:
        default_sources = ["github", "google", "wayback", "linkedin", "dns",
                           "shodan", "github_secrets", "stackoverflow"]
        active_sources = [s for s in default_sources
                          if src_cfg.get(s, {}).get("enabled", True)]

    github_token = args.github_token or src_cfg.get("github", {}).get("token") or os.environ.get("GITHUB_TOKEN")
    shodan_key = args.shodan_key or src_cfg.get("shodan", {}).get("api_key") or os.environ.get("SHODAN_API_KEY")

    out_cfg = cfg.get("output", {})
    html_output = args.html or (out_cfg.get("html_file") if out_cfg.get("html") else None)
    json_output = args.output or out_cfg.get("json")

    cve_enabled = (not args.no_cve) and cfg.get("cve_lookup", {}).get("enabled", True)
    cache_enabled = (not args.no_cache) and cfg.get("cache", {}).get("enabled", True)
    cache_ttl = cfg.get("cache", {}).get("ttl_static", 86400)

    report = TerminalReport(target, domain, verbose=args.verbose)
    report.print_banner()

    # --- COLLECTION PHASE ---
    all_data = []
    cache_file = f".recon_cache_{domain}.json"

    if args.resume:
        cache_file = args.resume
        if not os.path.exists(cache_file):
            report.error(f"Cache file not found: {cache_file}")
            sys.exit(1)
        with open(cache_file) as f:
            all_data = json.load(f)
        report.status(f"Resumed from cache: {cache_file} ({len(all_data)} data points)")

    if not args.resume:
        # Try SQLite cache first
        sqlite_cache = None
        if cache_enabled:
            try:
                from utils.cache import ReconCache
                sqlite_cache = ReconCache()
                sqlite_cache.clear_expired()
            except Exception:
                sqlite_cache = None

        def _cached_collect(source_key, collector_fn):
            if sqlite_cache:
                cached = sqlite_cache.get(source_key, domain)
                if cached is not None:
                    return cached
            data = collector_fn()
            if sqlite_cache:
                sqlite_cache.set(source_key, domain, data, ttl=cache_ttl)
            return data

        # Build collector list
        collectors_to_run = []
        if "github" in active_sources:
            gh = GitHubCollector(target, domain, token=github_token)
            collectors_to_run.append(("github", lambda: _cached_collect("github", gh.collect)))
        if "google" in active_sources:
            gd = GoogleDorksCollector(target, domain)
            collectors_to_run.append(("google", lambda: _cached_collect("google", gd.collect)))
        if "wayback" in active_sources:
            wb = WaybackCollector(domain)
            collectors_to_run.append(("wayback", lambda: _cached_collect("wayback", wb.collect)))
        if "linkedin" in active_sources:
            li = LinkedInCollector(target, domain)
            collectors_to_run.append(("linkedin", lambda: _cached_collect("linkedin", li.collect)))
        if "dns" in active_sources:
            dns = DNSCollector(domain)
            collectors_to_run.append(("dns", lambda: _cached_collect("dns", dns.collect)))
        if "shodan" in active_sources:
            sh = ShodanCollector(domain, api_key=shodan_key)
            collectors_to_run.append(("shodan", lambda: _cached_collect("shodan", sh.collect)))
        if "github_secrets" in active_sources:
            ghs = GitHubSecretsCollector(target, domain, token=github_token)
            collectors_to_run.append(("github_secrets", lambda: _cached_collect("github_secrets", ghs.collect)))
        if "stackoverflow" in active_sources:
            so = StackOverflowCollector(target, domain)
            collectors_to_run.append(("stackoverflow", lambda: _cached_collect("stackoverflow", so.collect)))

        # Run all collectors in parallel
        report.status(f"Running {len(collectors_to_run)} collectors in parallel...")
        from collectors.async_runner import run_collectors_parallel
        results = run_collectors_parallel(collectors_to_run)

        label_names = {
            "github": "GitHub", "google": "Google Dorks", "wayback": "Wayback Machine",
            "linkedin": "LinkedIn", "dns": "DNS/crt.sh", "shodan": "Shodan",
            "github_secrets": "GitHub Secrets", "stackoverflow": "Stack Overflow",
        }
        for label, data in results.items():
            all_data.extend(data)
            report.source_done(label_names.get(label, label), len(data))

        if not all_data:
            report.error("No data collected. Check network connectivity or try different sources.")
            sys.exit(1)

        with open(cache_file, "w") as f:
            json.dump(all_data, f)
        report.status(f"Raw data cached to {cache_file} (use --resume {cache_file} to skip collection)")

    report.status(f"Total raw data points collected: {len(all_data)}")

    # --- ANALYSIS PHASE ---
    backend = "Anthropic" if llm == "anthropic" else f"Ollama ({ollama_model})"
    report.status(f"Running semantic analysis with {backend}...")
    engine = SemanticEngine(
        api_key=args.anthropic_key,
        llm=llm,
        ollama_model=ollama_model,
        ollama_url=ollama_url,
    )
    findings = engine.analyze(target, domain, all_data)

    # --- CVE ENRICHMENT ---
    if cve_enabled:
        report.status("Looking up CVEs for detected technologies...")
        try:
            from analysis.cve_lookup import enrich_findings_with_cves
            enriched = enrich_findings_with_cves(
                findings.tech_stack + findings.attack_surface + findings.exposed_assets
            )
            if enriched:
                total_new = sum(len(cves) for _, cves in enriched)
                report.status(f"Added {total_new} CVEs across {len(enriched)} findings")
        except Exception as e:
            report.error(f"CVE lookup failed: {e}")

    # --- CORRELATION ENGINE ---
    graph_data = None
    attack_paths = None
    try:
        from analysis.correlation_engine import CorrelationEngine
        ce = CorrelationEngine()
        ce.build_from_findings(findings)
        graph_data = ce.to_dict()
        attack_paths = ce.find_attack_paths()
        if attack_paths:
            report.status(f"Identified {len(attack_paths)} potential attack paths")
    except Exception as e:
        report.error(f"Correlation engine failed: {e}")

    # --- OUTPUT PHASE ---
    report.print_findings(findings)

    if json_output:
        report.save_to_file(findings, json_output)
        report.status(f"JSON report saved to {json_output}")

    if html_output:
        try:
            os.makedirs(os.path.dirname(os.path.abspath(html_output)), exist_ok=True)
            from output.html_report import save_html_report
            save_html_report(findings, html_output, graph_data=graph_data, attack_paths=attack_paths)
            report.status(f"HTML report saved to {html_output}")
        except Exception as e:
            report.error(f"HTML report failed: {e}")


if __name__ == "__main__":
    main()
