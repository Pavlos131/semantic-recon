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
from collectors.paste_collector import PasteCollector
from collectors.hibp_collector import HIBPCollector
from collectors.whois_collector import WHOISCollector
from collectors.techfingerprint_collector import TechFingerprintCollector
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
  python recon.py --target "ACME" --domain acme.com --diff report_old.json --output report_new.json
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
        choices=["github", "google", "wayback", "linkedin", "dns", "shodan",
                 "github_secrets", "stackoverflow", "paste", "hibp", "whois",
                 "techfingerprint"],
        default=None,
        help="Data sources to use"
    )
    parser.add_argument("--shodan-key", default=None, help="Shodan API key")
    parser.add_argument("--hibp-key", default=None, help="HaveIBeenPwned API key")
    parser.add_argument("--securitytrails-key", default=None, help="SecurityTrails API key (for WHOIS history)")
    parser.add_argument("--output", default=None, help="Save JSON report to file")
    parser.add_argument("--html", default=None, help="Save HTML report to file (e.g. report.html)")
    parser.add_argument("--md", default=None, help="Save Markdown report to file (e.g. report.md)")
    parser.add_argument("--verbose", action="store_true", help="Show raw collected data")
    parser.add_argument("--llm", choices=["anthropic", "ollama"], default=None,
                        help="LLM backend to use")
    parser.add_argument("--ollama-model", default=None, help="Ollama model name")
    parser.add_argument("--ollama-url", default=None, help="Ollama server URL")
    parser.add_argument("--interactive", "-i", action="store_true",
                        help="Interactive mode — select options via menu")
    parser.add_argument("--select-sources", "-s", action="store_true",
                        help="Interactively select which sources to use")
    parser.add_argument("--resume", default=None, metavar="FILE",
                        help="Skip collection, load raw data from a cache file")
    parser.add_argument("--no-cve", action="store_true", help="Skip CVE auto-lookup")
    parser.add_argument("--no-cache", action="store_true", help="Ignore collector cache")
    parser.add_argument("--diff", default=None, metavar="FILE",
                        help="Compare results with a previous JSON report and show what changed")

    args = parser.parse_args()

    # Interactive mode — trigger if --interactive or no target/domain given
    if args.interactive or (not args.target and not args.domain and not args.config and not args.resume):
        from interactive import prompt
        args = prompt(args)
    elif args.select_sources:
        from interactive import select_sources
        args = select_sources(args)

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
        # techfingerprint is opt-in only (makes live HTTP requests to target)
        default_sources = ["github", "google", "wayback", "linkedin", "dns",
                           "shodan", "github_secrets", "stackoverflow", "paste", "hibp", "whois"]
        active_sources = [s for s in default_sources
                          if src_cfg.get(s, {}).get("enabled", True)]

    github_token = args.github_token or src_cfg.get("github", {}).get("token") or os.environ.get("GITHUB_TOKEN")
    shodan_key = args.shodan_key or src_cfg.get("shodan", {}).get("api_key") or os.environ.get("SHODAN_API_KEY")
    hibp_key = args.hibp_key or src_cfg.get("hibp", {}).get("api_key") or os.environ.get("HIBP_API_KEY")
    st_key = args.securitytrails_key or src_cfg.get("whois", {}).get("securitytrails_key") or os.environ.get("SECURITYTRAILS_API_KEY")

    out_cfg = cfg.get("output", {})
    html_output = args.html or (out_cfg.get("html_file") if out_cfg.get("html") else None)
    json_output = args.output or out_cfg.get("json")
    md_output = args.md or out_cfg.get("md")

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
        if "paste" in active_sources:
            pc = PasteCollector(target, domain, github_token=github_token)
            collectors_to_run.append(("paste", lambda: _cached_collect("paste", pc.collect)))
        if "hibp" in active_sources:
            hibp = HIBPCollector(domain, api_key=hibp_key)
            collectors_to_run.append(("hibp", lambda: _cached_collect("hibp", hibp.collect)))
        if "whois" in active_sources:
            wh = WHOISCollector(domain, securitytrails_key=st_key)
            collectors_to_run.append(("whois", lambda: _cached_collect("whois", wh.collect)))
        if "techfingerprint" in active_sources:
            tf = TechFingerprintCollector(domain)
            collectors_to_run.append(("techfingerprint", lambda: _cached_collect("techfingerprint", tf.collect)))

        # Run all collectors in parallel
        report.status(f"Running {len(collectors_to_run)} collectors in parallel...")
        from collectors.async_runner import run_collectors_parallel
        results = run_collectors_parallel(collectors_to_run)

        label_names = {
            "github": "GitHub", "google": "Google Dorks", "wayback": "Wayback Machine",
            "linkedin": "LinkedIn", "dns": "DNS/crt.sh+HackerTarget+RapidDNS", "shodan": "Shodan",
            "github_secrets": "GitHub Secrets", "stackoverflow": "Stack Overflow",
            "paste": "Paste/Gist Scanner", "hibp": "HaveIBeenPwned", "whois": "WHOIS",
            "techfingerprint": "Tech Fingerprinting",
        }
        for label, data in results.items():
            all_data.extend(data)
            report.source_done(label_names.get(label, label), len(data))

        # HIBP email enrichment — run after collection to use discovered emails
        if "hibp" in active_sources and hibp_key:
            report.status("Checking discovered emails against HIBP...")
            extra = hibp.extract_emails_from_data(all_data)
            new_items = [x for x in extra if x not in all_data]
            all_data.extend(new_items)
            if new_items:
                report.source_done("HIBP (email enrichment)", len(new_items))

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

    if md_output:
        try:
            from output.markdown_report import save_markdown_report
            save_markdown_report(findings, md_output)
            report.status(f"Markdown report saved to {md_output}")
        except Exception as e:
            report.error(f"Markdown report failed: {e}")

    if args.diff:
        try:
            from analysis.diff_engine import load_json_report, compute_diff
            prev = load_json_report(args.diff)
            prev["_source_file"] = args.diff
            diff_result = compute_diff(findings, prev)
            report.print_diff(diff_result)
        except FileNotFoundError:
            report.error(f"Diff file not found: {args.diff}")
        except Exception as e:
            report.error(f"Diff failed: {e}")


if __name__ == "__main__":
    main()
