# Semantic Recon Engine

LLM-powered OSINT tool that **infers** attack surface from unstructured text — not just keyword matching.

## Install

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Basic usage
export ANTHROPIC_API_KEY="sk-ant-..."
python recon.py --target "Cloudflare" --domain cloudflare.com

# With GitHub token (higher rate limits)
python recon.py --target "Tesla" --domain tesla.com --github-token ghp_xxx

# Specific sources only
python recon.py --target "ACME" --domain acme.com --sources github wayback

# Save JSON report
python recon.py --target "Target" --domain target.com --output report.json

# Verbose (show evidence sources)
python recon.py --target "Target" --domain target.com --verbose
```

## Sources

| Source | What it collects |
|--------|-----------------|
| **GitHub** | Repos, commits, code files, issues mentioning the domain |
| **Google Dorks** | Tech stack hints, job postings, exposed files, employee info |
| **Wayback Machine** | Historical snapshots, deleted pages, old robots.txt |
| **LinkedIn** | Employee roles, job postings (via Google), tech stack signals |

## What Claude Infers

- **Tech Stack** — from job postings, commit messages, config files
- **Internal Tools** — CI/CD, monitoring, auth systems mentioned indirectly
- **Employee Intel** — who owns what system (spear phishing targets)
- **Security Posture** — maturity score based on visible security signals
- **Attack Surface** — specific entry points with relevant CVEs/MITRE techniques
- **Exposed Assets** — historically accessible files/endpoints
- **Temporal Insights** — what changed over time (legacy tech still in use)

## Architecture

```
recon.py
├── collectors/
│   ├── github_collector.py    # GitHub API
│   ├── google_collector.py    # Google Dorks scraping
│   ├── wayback_collector.py   # Wayback Machine CDX API
│   └── linkedin_collector.py  # LinkedIn via Google
├── analysis/
│   └── semantic_engine.py     # Claude-powered analysis
└── output/
    └── terminal.py            # Rich terminal report
```

## Legal

For authorized penetration testing and red team exercises only.
Always obtain written permission before running against any target.
