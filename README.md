# Semantic Recon Engine

LLM-powered OSINT tool that **infers** attack surface from unstructured text — not just keyword matching.

Instead of simple grep-based matching, it uses Claude (or a local Ollama model) to reason about indirect signals: a job posting mentioning "Jenkins 2.3" implies a specific CVE, a Wayback snapshot of `/admin/build/` implies Drupal 7, etc.

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

### Quick start (Anthropic)
```bash
export ANTHROPIC_API_KEY="sk-ant-..."
python recon.py --target "Cloudflare" --domain cloudflare.com
```

### With local Ollama (free)
```bash
ollama pull llama3
ollama serve
python recon.py --target "Cloudflare" --domain cloudflare.com --llm ollama --ollama-model llama3
```

### HTML report
```bash
python recon.py --target "Tesla" --domain tesla.com --html report.html
```

### Resume after crash (skip collection)
```bash
python recon.py --target "Tesla" --domain tesla.com --resume .recon_cache_tesla.com.json
```

### Using a config file
```bash
cp config.yaml myconfig.yaml
# edit myconfig.yaml with your target/settings
python recon.py --config myconfig.yaml
```

### All options
```
--target          Company name
--domain          Target domain (e.g. tesla.com)
--config          Path to YAML config file
--sources         Specific sources: github google wayback linkedin dns shodan github_secrets stackoverflow
--llm             anthropic (default) or ollama
--ollama-model    Ollama model name (default: llama3)
--ollama-url      Ollama server URL (default: http://localhost:11434)
--github-token    GitHub API token (increases rate limits)
--shodan-key      Shodan API key
--html            Save interactive HTML report to file
--output          Save JSON report to file
--resume FILE     Skip collection, load from cache file
--no-cve          Skip CVE auto-lookup
--no-cache        Ignore SQLite cache
--verbose         Show evidence sources in output
```

---

## Sources

| Source | What it collects |
|--------|-----------------|
| **GitHub** | Repos, commits, code files, issues mentioning the domain |
| **Google Dorks** | Tech stack hints, job postings, exposed files, employee info |
| **Wayback Machine** | Historical snapshots, deleted pages, old robots.txt |
| **LinkedIn** | Employee roles, job postings (via Google) |
| **DNS / crt.sh** | Subdomains from certificate transparency logs, MX/TXT records |
| **Shodan** | Open ports, banners, software versions, known vulns |
| **GitHub Secrets** | Leaked API keys, tokens, passwords in public repos |
| **Stack Overflow** | Internal tool references from employee questions |

All sources run **in parallel** via asyncio.

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

---

## Architecture

```
recon.py                        ← CLI entry point
├── collectors/
│   ├── github_collector.py     ← GitHub API (repos, commits, code, issues)
│   ├── google_collector.py     ← Google Dorks scraping
│   ├── wayback_collector.py    ← Wayback Machine CDX API
│   ├── linkedin_collector.py   ← LinkedIn via Google
│   ├── dns_collector.py        ← crt.sh + dnspython
│   ├── shodan_collector.py     ← Shodan API
│   ├── github_secrets_collector.py  ← Leaked secrets scanner
│   ├── stackoverflow_collector.py   ← Stack Overflow API
│   └── async_runner.py         ← Parallel execution via ThreadPoolExecutor
├── analysis/
│   ├── semantic_engine.py      ← LLM analysis → structured findings
│   ├── correlation_engine.py   ← Knowledge graph + attack path finder
│   └── cve_lookup.py           ← NVD API auto-enrichment
├── output/
│   ├── terminal.py             ← Rich colored terminal report
│   └── html_report.py          ← Interactive D3.js HTML report
├── utils/
│   └── cache.py                ← SQLite cache with TTL
└── config.yaml                 ← Example config file
```

---

## Environment Variables

```bash
ANTHROPIC_API_KEY=sk-ant-...   # required for Anthropic backend
GITHUB_TOKEN=ghp_...           # optional, increases GitHub rate limits
SHODAN_API_KEY=...             # optional
```

---

## Legal

For **authorized penetration testing and red team exercises only**.
Always obtain written permission before running against any target.
