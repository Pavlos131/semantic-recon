"""
Paste Collector - scans GitHub Gists and paste sites for leaked credentials/configs
mentioning the target domain.

Uses:
- GitHub Gist search API
- Google dorks for pastebin.com, gist.github.com, hastebin.com
"""

import requests
import time
import re


SENSITIVE_PATTERNS = [
    r'password\s*[=:]\s*\S+',
    r'passwd\s*[=:]\s*\S+',
    r'api[_\-]?key\s*[=:]\s*\S+',
    r'secret\s*[=:]\s*\S+',
    r'token\s*[=:]\s*\S+',
    r'aws[_\-]?access[_\-]?key',
    r'aws[_\-]?secret',
    r'private[_\-]?key',
    r'-----BEGIN',
    r'Authorization:\s*Bearer',
    r'AKIA[0-9A-Z]{16}',           # AWS access key
    r'ghp_[a-zA-Z0-9]{36}',        # GitHub PAT
    r'sk-[a-zA-Z0-9]{32,}',        # OpenAI / Anthropic key pattern
    r'smtp[_\-]?pass',
    r'db[_\-]?pass',
    r'database[_\-]?url',
    r'mongodb\+srv://',
    r'postgres(?:ql)?://',
    r'mysql://',
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in SENSITIVE_PATTERNS]


def _has_sensitive_content(text: str) -> bool:
    return any(p.search(text) for p in COMPILED_PATTERNS)


class PasteCollector:
    def __init__(self, target: str, domain: str, github_token: str = None):
        self.target = target
        self.domain = domain
        self.results = []
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Mozilla/5.0 (compatible; security-research)",
        }
        if github_token:
            self.headers["Authorization"] = f"token {github_token}"

    def _get(self, url, params=None, headers=None):
        try:
            r = requests.get(url, params=params, headers=headers or self.headers, timeout=10)
            if r.status_code in (403, 429):
                return None
            r.raise_for_status()
            return r
        except Exception:
            return None

    def collect(self) -> list:
        self._search_github_gists()
        self._search_google_pastes()
        return self.results

    def _search_github_gists(self):
        """Search GitHub Gists for domain references."""
        queries = [
            self.domain,
            f'"{self.domain}" password',
            f'"{self.domain}" api_key',
            f'"{self.domain}" token',
        ]

        for q in queries:
            r = self._get(
                "https://api.github.com/search/code",
                params={"q": f'{q} filename:*.env OR filename:*.cfg OR filename:*.conf OR filename:*.yaml', "per_page": 5}
            )
            if not r:
                time.sleep(1)
                continue

            data = r.json()
            for item in data.get("items", []):
                repo = item.get("repository", {})
                name = item.get("name", "")
                path = item.get("path", "")
                html_url = item.get("html_url", "")

                # Fetch raw content to check for sensitive patterns
                raw_url = item.get("url", "")
                content_text = ""
                if raw_url:
                    cr = self._get(raw_url)
                    if cr:
                        try:
                            content_b64 = cr.json().get("content", "")
                            import base64
                            content_text = base64.b64decode(content_b64.replace("\n", "")).decode("utf-8", errors="ignore")
                        except Exception:
                            pass

                sensitive = _has_sensitive_content(content_text) if content_text else False
                sensitivity_tag = " [SENSITIVE CONTENT DETECTED]" if sensitive else ""

                text = (f"GitHub file mentioning {self.domain}: {name} in repo {repo.get('full_name', '')} "
                        f"| path: {path}{sensitivity_tag}")
                self.results.append({
                    "source": "github_gist_leak",
                    "url": html_url,
                    "text": text,
                    "date": ""
                })
            time.sleep(1)

        # Search Gists specifically
        r = self._get(
            "https://api.github.com/search/code",
            params={"q": f'"{self.domain}"', "per_page": 10}
        )
        if r:
            for item in r.json().get("items", []):
                if "gist.github.com" not in item.get("repository", {}).get("html_url", ""):
                    continue
                text = (f"GitHub Gist containing {self.domain}: {item.get('name', '')} "
                        f"in {item.get('repository', {}).get('full_name', '')}")
                self.results.append({
                    "source": "github_gist_leak",
                    "url": item.get("html_url", ""),
                    "text": text,
                    "date": ""
                })
        time.sleep(1)

    def _search_google_pastes(self):
        """Use Google to find domain references on paste sites."""
        paste_sites = [
            "pastebin.com",
            "gist.github.com",
            "hastebin.com",
            "paste.ee",
        ]

        dorks = []
        for site in paste_sites:
            dorks.append(f'site:{site} "{self.domain}"')
            dorks.append(f'site:{site} "{self.domain}" password')

        for dork in dorks:
            r = self._get(
                "https://www.google.com/search",
                params={"q": dork, "num": 5},
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}
            )
            if not r:
                time.sleep(2)
                continue

            # Extract URLs from search results (basic)
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            for a in soup.select("a[href]"):
                href = a.get("href", "")
                if any(site in href for site in paste_sites) and self.domain in href:
                    text = f"Paste site result for '{dork}': {href}"
                    self.results.append({
                        "source": "paste_google",
                        "url": href,
                        "text": text,
                        "date": ""
                    })

            time.sleep(3)  # Google rate limiting
