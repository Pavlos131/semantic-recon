# Semantic Recon Engine — Development Briefing

## Τι είναι

LLM-powered OSINT tool για authorized penetration testing recon phase.
Αντί για keyword-based matching (όπως Maltego, theHarvester), χρησιμοποιεί Claude για να **συμπεράνει** attack surface από unstructured text.

Παράδειγμα: Διαβάζει ένα job posting "Looking for DevOps engineer familiar with Jenkins 2.3 and HashiCorp Vault" και συμπεραίνει:
- Jenkins 2.3 → CVE-2024-23897 (unauthenticated RCE)
- HashiCorp Vault → συγκεκριμένη attack surface
- Έχουν internal CI/CD pipeline

## Τρέχουσα κατάσταση (MVP — υπάρχει ήδη)

### Δομή
```
semantic_recon/
├── recon.py                    ← CLI entry point
├── requirements.txt
├── collectors/
│   ├── github_collector.py     ← GitHub API (repos, commits, code, issues)
│   ├── google_collector.py     ← Google Dorks scraping (14 dorks)
│   ├── wayback_collector.py    ← Wayback Machine CDX API
│   └── linkedin_collector.py   ← LinkedIn intel μέσω Google
├── analysis/
│   └── semantic_engine.py      ← Claude API analysis → structured findings
└── output/
    └── terminal.py             ← Rich colored terminal report
```

### Τι κάνει το MVP
1. Παίρνει `--target "Company" --domain company.com` από CLI
2. Τρέχει όλους τους collectors παράλληλα (serial αυτή τη στιγμή)
3. Στέλνει raw data στο Claude με structured prompt
4. Claude επιστρέφει JSON με findings ανά κατηγορία
5. Εκτυπώνει color-coded terminal report

### Dataclass findings
```python
@dataclass
class Finding:
    category: str
    title: str
    description: str
    confidence: str  # HIGH / MEDIUM / LOW
    inference_chain: str
    evidence_sources: List[str]
    attack_relevance: str
    cves_or_techniques: List[str]

@dataclass
class ReconReport:
    target: str
    domain: str
    tech_stack: List[Finding]
    internal_tools: List[Finding]
    employee_intel: List[Finding]
    security_posture: List[Finding]
    attack_surface: List[Finding]
    exposed_assets: List[Finding]
    temporal_insights: List[Finding]
    summary: str
    security_maturity_score: int  # 0-10
```

---

## Τι πρέπει να υλοποιηθεί (TODO)

### Priority 1 — Νέοι Collectors

#### DNS + Certificate Transparency
```python
# collectors/dns_collector.py
# - crt.sh API: https://crt.sh/?q=%.domain.com&output=json
# - Subdomain enumeration από CT logs
# - DNS records: MX, TXT (SPF/DMARC misconfigs), NS
# - dnspython library
```

#### Shodan
```python
# collectors/shodan_collector.py
# - shodan library (pip install shodan)
# - Search: hostname:domain.com
# - Εξάγει: open ports, banners, software versions, vulns
# - Requires: SHODAN_API_KEY env var
```

#### GitHub Secrets Scanner
```python
# collectors/github_secrets_collector.py
# - Ψάχνει για leaked secrets στο GitHub
# - Patterns: API keys, passwords, tokens σε code
# - Χρησιμοποιεί GitHub search API με regex patterns
# - Ελέγχει και git history (force-pushed commits)
```

#### Stack Overflow
```python
# collectors/stackoverflow_collector.py
# - Stack Overflow API: https://api.stackexchange.com/2.3/search
# - Ψάχνει ερωτήσεις από employees που αναφέρουν internal systems
# - Αποκαλύπτει internal tooling, architecture decisions
```

### Priority 2 — Cross-Source Correlation Engine

```python
# analysis/correlation_engine.py

class CorrelationEngine:
    """
    Συσχετίζει entities across sources.
    
    Παράδειγμα:
    - GitHub user "jsmith" → commits στο domain
    - LinkedIn "John Smith" → DevOps at Company
    - Google result → "John Smith" μιλάει σε conference για Kubernetes
    → ΣΥΜΠΕΡΑΣΜΑ: John Smith είναι ο infrastructure lead, 
                  responsible για Kubernetes cluster,
                  καλός στόχος για spear phishing
    
    Entities: Person, Technology, Service, Repository, Endpoint
    Relations: uses, knows, responsible_for, exposed_by, connects_to
    """
    
    def build_graph(self, all_findings: List[Finding]) -> nx.DiGraph:
        # Χρησιμοποίησε networkx
        # Nodes: entities
        # Edges: relations με confidence weight
        pass
    
    def find_attack_paths(self, graph: nx.DiGraph) -> List[AttackPath]:
        # Βρες paths από external → internal assets
        pass
```

### Priority 3 — Async/Concurrent Collectors

```python
# Αντικατάσταση του serial collection με asyncio
import asyncio
import aiohttp

async def collect_all(target, domain):
    tasks = [
        github_collector.collect_async(),
        google_collector.collect_async(),
        wayback_collector.collect_async(),
        dns_collector.collect_async(),
        shodan_collector.collect_async(),
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results
```

### Priority 4 — Caching Layer

```python
# utils/cache.py
# SQLite-based cache για να μην ξανακάνει requests
# Cache key: hash(source + query)
# TTL: 24 ώρες για static data, 1 ώρα για dynamic
# 
# Χρήση:
# @cached(ttl=3600)
# def collect(self): ...
```

### Priority 5 — CVE Auto-Lookup

```python
# analysis/cve_lookup.py
# NVD API: https://services.nvd.nist.gov/rest/json/cves/2.0
# Όταν το Claude εντοπίσει technology + version,
# αυτόματο lookup στο NVD για known CVEs
# Enriches findings με CVSS score, description, PoC links
```

### Priority 6 — HTML Report με D3.js

```
output/html_report.py
- Jinja2 template
- D3.js force-directed graph (knowledge graph των entities)
- MITRE ATT&CK heatmap
- Interactive filtering ανά confidence/category
- Export σε PDF
```

### Priority 7 — Config File

```yaml
# config.yaml (αντί για CLI args)
target: "Company Name"
domain: "company.com"

sources:
  github:
    enabled: true
    token: "${GITHUB_TOKEN}"
  shodan:
    enabled: true
    api_key: "${SHODAN_API_KEY}"
  google:
    enabled: true
    delay_min: 2
    delay_max: 5

llm:
  provider: "anthropic"  # ή "ollama"
  model: "claude-opus-4-5"
  # ollama_model: "llama3"

output:
  terminal: true
  html: true
  json: "./reports/report.json"
```

---

## Τεχνικές λεπτομέρειες

### Claude Prompt Strategy
Το σημαντικό είναι το **inference chain** — το Claude πρέπει να εξηγεί γιατί κατέληξε σε κάθε finding, όχι μόνο τι βρήκε. Αυτό γίνεται με το system prompt που ορίζει τον ρόλο "senior pentester που σκέφτεται σαν attacker".

### Rate Limiting
- GitHub API: 60 req/hour unauthenticated, 5000 με token
- Google: Random delays 2-5 sec, User-Agent rotation
- Wayback CDX: Γενικά γενναιόδωρο
- Shodan: Ανάλογα με plan

### Dependencies
```
anthropic>=0.25.0
requests>=2.31.0
beautifulsoup4>=4.12.0
rich>=13.7.0
python-dotenv>=1.0.0
networkx>=3.0          # για correlation graph
dnspython>=2.4.0       # για DNS collector
shodan>=1.28.0         # για Shodan collector
aiohttp>=3.9.0         # για async collectors
jinja2>=3.1.0          # για HTML report
```

### Environment Variables
```bash
ANTHROPIC_API_KEY=sk-ant-...
GITHUB_TOKEN=ghp_...          # optional, higher rate limits
SHODAN_API_KEY=...            # optional
```

---

## Πώς να τρέξεις το MVP τώρα

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY="sk-ant-..."
python recon.py --target "Tesla" --domain tesla.com --github-token ghp_xxx
python recon.py --target "Cloudflare" --domain cloudflare.com --verbose
python recon.py --target "Target" --domain example.com --sources github wayback --output report.json
```

---

## Σημείωση

Το tool είναι για **authorized penetration testing και red team exercises μόνο**.
Πάντα να έχεις γραπτή άδεια πριν τρέξεις against οποιοδήποτε target.
