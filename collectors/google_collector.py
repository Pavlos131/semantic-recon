"""
Google Dorks Collector - uses scraping to run targeted dorks
"""

import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import quote_plus


class GoogleDorksCollector:
    def __init__(self, target: str, domain: str):
        self.target = target
        self.domain = domain
        self.results = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept-Language": "en-US,en;q=0.9",
        }

    def _search(self, dork: str, dork_label: str) -> list:
        """Execute a single dork and return results"""
        url = f"https://www.google.com/search?q={quote_plus(dork)}&num=10&hl=en"
        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code != 200:
                return []

            soup = BeautifulSoup(r.text, "html.parser")
            results = []

            # Extract search result snippets
            for g in soup.select("div.g")[:8]:
                title_el = g.select_one("h3")
                snippet_el = g.select_one("div.VwiC3b, span.aCOpRe, div[data-sncf]")
                link_el = g.select_one("a[href]")

                title = title_el.get_text() if title_el else ""
                snippet = snippet_el.get_text() if snippet_el else ""
                link = link_el["href"] if link_el else ""

                if title or snippet:
                    results.append({
                        "source": f"google_dork:{dork_label}",
                        "url": link,
                        "text": f"[{dork_label}] Title: {title} | Snippet: {snippet[:400]}",
                        "date": ""
                    })

            return results
        except Exception as e:
            return []

    def collect(self) -> list:
        dorks = [
            # Tech stack discovery
            (f'site:{self.domain} "powered by" OR "built with" OR "running on"', "tech_stack"),
            (f'site:{self.domain} filetype:xml OR filetype:json OR filetype:yaml', "config_files"),
            (f'site:{self.domain} "api" OR "swagger" OR "openapi" OR "graphql"', "api_discovery"),

            # Job postings = tech intel
            (f'"{self.target}" site:linkedin.com/jobs OR site:glassdoor.com "engineer" OR "developer"', "job_postings"),
            (f'"{self.target}" "we use" OR "our stack" OR "our infrastructure" OR "our platform"', "tech_mentions"),

            # Leaked/exposed info
            (f'site:{self.domain} "error" OR "exception" OR "stack trace" OR "debug"', "error_pages"),
            (f'site:{self.domain} intitle:"index of" OR inurl:"/.git/" OR inurl:"/config/"', "exposed_dirs"),
            (f'"{self.domain}" site:pastebin.com OR site:gist.github.com OR site:hastebin.com', "paste_sites"),

            # Employee intel
            (f'"{self.target}" site:linkedin.com/in "infrastructure" OR "security" OR "devops"', "employee_recon"),
            (f'"{self.target}" "@{self.domain}" site:twitter.com OR site:x.com', "social_mentions"),

            # Historical/cached
            (f'cache:{self.domain}', "cached_pages"),
            (f'"{self.domain}" "internal" OR "intranet" OR "vpn" OR "confluence" OR "jira"', "internal_tools"),

            # Blog posts / tech talks
            (f'"{self.target}" site:medium.com OR site:dev.to OR site:engineering.{self.domain}', "tech_blog"),
            (f'"{self.target}" site:youtube.com "talk" OR "conference" OR "presentation"', "conference_talks"),
        ]

        for dork, label in dorks:
            hits = self._search(dork, label)
            self.results.extend(hits)
            # Random delay to avoid detection
            time.sleep(random.uniform(2, 5))

        return self.results
