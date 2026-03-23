# Semantic Recon Engine

LLM-powered OSINT tool that **infers** attack surface from unstructured text — not just keyword matching.

Instead of simple grep-based matching, it uses Claude (or a local Ollama model) to reason about indirect signals: a job posting mentioning "Jenkins 2.3" implies a specific CVE, a Wayback snapshot of `/admin/build/` implies Drupal 7, a Stack Overflow question from an employee reveals internal infrastructure, etc.

> For authorized penetration testing and red team exercises only.

---

## Install

```bash
git clone git@github.com:Pavlos131/semantic-recon.git
cd semantic-recon
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

---

## Usage

### Interactive mode (recommended)
```bash
python recon.py
```
Launches a menu where you select target, sources, LLM, and output options.

### CLI mode
```bash
# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."
python recon.py --target "Cloudflare" --domain cloudflare.com

# Local Ollama (free)
ollama pull llama3
python recon.py --target "Cloudflare" --domain cloudflare.com --llm ollama --ollama-model llama3

# HTML report
python recon.py --target "Tesla" --domain tesla.com --html report.html

# Resume after crash (skip collection)
python recon.py --target "Tesla" --domain tesla.com --resume .recon_cache_tesla.com.json

# Config file
python recon.py --config config.yaml

# Specific sources only
python recon.py --target "ACME" --domain acme.com --sources github wayback dns whois

# Include tech fingerprinting (opt-in — makes live HTTP requests to target)
python recon.py --target "ACME" --domain acme.com --sources github wayback techfingerprint

# Diff mode — compare two runs and show what changed
python recon.py --target "ACME" --domain acme.com --output report_new.json --diff report_old.json
```

### All options
```
--target                Company name
--domain                Target domain (e.g. tesla.com)
--config                Path to YAML config file
--interactive / -i      Force interactive menu
--sources               Specific sources (see list below)
--llm                   anthropic (default) or ollama
--ollama-model          Ollama model name (default: llama3)
--ollama-url            Ollama server URL (default: http://localhost:11434)
--github-token          GitHub API token (increases rate limits)
--shodan-key            Shodan API key
--hibp-key              HaveIBeenPwned API key
--securitytrails-key    SecurityTrails API key (WHOIS history)
--html                  Save interactive HTML report
--output                Save JSON report
--resume FILE           Skip collection, load from cache file
--no-cve                Skip CVE auto-lookup
--no-cache              Ignore SQLite cache
--verbose               Show evidence sources in output
--diff FILE             Compare with a previous JSON report and show what changed
```

---

## Sources

| Source | What it collects | API key |
|--------|-----------------|---------|
| **GitHub** | Repos, commits, code files, issues | optional (higher rate limits) |
| **Google Dorks** | Tech stack hints, job postings, exposed files | — |
| **Wayback Machine** | Historical snapshots, deleted pages, old robots.txt | — |
| **LinkedIn** | Employee roles, job postings (via Google) | — |
| **DNS / crt.sh** | Subdomains from certificate transparency, MX/TXT records | — |
| **GitHub Secrets** | Leaked API keys, tokens, passwords in public repos | optional |
| **Stack Overflow** | Internal tool references from employee questions | — |
| **Paste / Gist** | Leaked configs/credentials on paste sites | optional |
| **HaveIBeenPwned** | Email breach lookup for domain employees | optional ($3.50/mo) |
| **WHOIS** | Registration history, DNS changes over time | optional (free tier) |
| **Shodan** | Open ports, banners, software versions, known vulns | required |
| **Tech Fingerprinting** | HTTP response headers, cookies, security headers, robots.txt | — |

> **Tech Fingerprinting** is **opt-in only** (not in defaults). It makes live HTTP requests directly to the target. Enable explicitly with `--sources techfingerprint` or combined with others.

All sources run **in parallel** via asyncio. Results are cached in SQLite (24h TTL).

---

## What the engine infers

| Category | Examples |
|----------|---------|
| **Tech Stack** | Frameworks, databases, languages from indirect signals |
| **Internal Tools** | CI/CD, monitoring, auth systems mentioned indirectly |
| **Employee Intel** | Who owns what system — spear phishing targets |
| **Security Posture** | Maturity score (0–10) based on visible security signals |
| **Attack Surface** | Entry points with relevant CVEs and MITRE ATT&CK techniques |
| **Exposed Assets** | Historically accessible files/endpoints |
| **Temporal Insights** | Legacy tech still in use, migrations in progress |

After analysis, the engine automatically:
- Looks up CVEs on NVD for detected technology versions
- Builds a knowledge graph and identifies attack paths (networkx)
- Merges findings across chunks: duplicates are consolidated, evidence sources combined, confidence boosted when multiple data chunks confirm the same finding
- Shows a `source_count` badge (e.g. `×3 sources`) when a finding was confirmed by multiple independent data segments

---

## Output

**Terminal** — color-coded Rich report with confidence levels, inference chains, CVEs, source count badges

**HTML report** (`--html report.html`) — interactive D3.js knowledge graph, attack paths, dark theme

**Diff report** (`--diff previous.json`) — highlights new findings, removed findings, and confidence changes between two runs

---

## Architecture

```
recon.py                        ← CLI entry point
interactive.py                  ← Interactive menu (questionary)
config.yaml                     ← Example config file
├── collectors/
│   ├── github_collector.py
│   ├── google_collector.py
│   ├── wayback_collector.py
│   ├── linkedin_collector.py
│   ├── dns_collector.py
│   ├── shodan_collector.py
│   ├── github_secrets_collector.py
│   ├── stackoverflow_collector.py
│   ├── paste_collector.py          ← Pastebin / GitHub Gist leak scanner
│   ├── hibp_collector.py           ← HaveIBeenPwned breach lookup
│   ├── whois_collector.py          ← WHOIS + DNS history
│   ├── techfingerprint_collector.py ← HTTP headers, cookies, robots.txt (opt-in)
│   └── async_runner.py             ← Parallel execution
├── analysis/
│   ├── semantic_engine.py      ← LLM analysis → structured findings + multi-chunk merge
│   ├── correlation_engine.py   ← Knowledge graph + attack paths
│   ├── cve_lookup.py           ← NVD CVE auto-enrichment
│   └── diff_engine.py          ← Compare two runs, surface changes
├── output/
│   ├── terminal.py             ← Rich terminal report
│   └── html_report.py          ← Interactive D3.js HTML report
└── utils/
    └── cache.py                ← SQLite cache with TTL
```

---

## Environment Variables

```bash
ANTHROPIC_API_KEY=sk-ant-...          # required for Anthropic backend
GITHUB_TOKEN=ghp_...                  # optional, higher GitHub rate limits
SHODAN_API_KEY=...                    # optional
HIBP_API_KEY=...                      # optional (haveibeenpwned.com)
SECURITYTRAILS_API_KEY=...            # optional (securitytrails.com free tier)
```

---

## Legal

For **authorized penetration testing and red team exercises only**.
Always obtain written permission before running against any target.
