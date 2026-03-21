"""
LinkedIn Collector - public profile scraping without login
Uses Google as intermediary + direct public pages
"""

import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import quote_plus


class LinkedInCollector:
    def __init__(self, target: str, domain: str):
        self.target = target
        self.domain = domain
        self.results = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }

    def _google_linkedin_search(self, query: str, label: str) -> list:
        """Use Google to find LinkedIn pages (avoids LinkedIn auth wall)"""
        full_query = f"site:linkedin.com {query}"
        url = f"https://www.google.com/search?q={quote_plus(full_query)}&num=10&hl=en"

        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code != 200:
                return []

            soup = BeautifulSoup(r.text, "html.parser")
            results = []

            for g in soup.select("div.g")[:8]:
                title_el = g.select_one("h3")
                snippet_el = g.select_one("div.VwiC3b, span.aCOpRe")
                link_el = g.select_one("a[href]")

                title = title_el.get_text() if title_el else ""
                snippet = snippet_el.get_text() if snippet_el else ""
                link = link_el["href"] if link_el else ""

                if "linkedin.com" in link and (title or snippet):
                    results.append({
                        "source": f"linkedin:{label}",
                        "url": link,
                        "text": f"[LinkedIn:{label}] {title} | {snippet[:400]}",
                        "date": ""
                    })

            return results
        except Exception:
            return []

    def _fetch_public_company_page(self) -> list:
        """Try to fetch the public LinkedIn company page"""
        slug = self.target.lower().replace(" ", "-").replace(".", "")
        url = f"https://www.linkedin.com/company/{slug}"

        try:
            r = requests.get(url, headers=self.headers, timeout=15)
            if r.status_code != 200:
                return []

            soup = BeautifulSoup(r.text, "html.parser")

            # Extract any visible text
            for tag in soup(["script", "style"]):
                tag.decompose()

            text = soup.get_text(separator=" ", strip=True)[:2000]

            if len(text) > 100:
                return [{
                    "source": "linkedin_company_page",
                    "url": url,
                    "text": f"LinkedIn company page for {self.target}: {text}",
                    "date": ""
                }]
        except Exception:
            pass
        return []

    def collect(self) -> list:
        # Security & infrastructure employees
        security_queries = [
            (f'"{self.target}" "security engineer" OR "penetration tester" OR "CISO" OR "SOC"', "security_staff"),
            (f'"{self.target}" "devops" OR "infrastructure" OR "SRE" OR "platform engineer"', "infra_staff"),
            (f'"{self.target}" "software architect" OR "principal engineer" OR "tech lead"', "senior_tech"),
        ]

        # Job postings (gold mine for tech stack)
        job_queries = [
            (f'"{self.target}" jobs "kubernetes" OR "docker" OR "terraform" OR "ansible"', "jobs_infra"),
            (f'"{self.target}" jobs "python" OR "golang" OR "java" OR "nodejs"', "jobs_dev"),
            (f'"{self.target}" jobs "aws" OR "azure" OR "gcp" OR "cloud"', "jobs_cloud"),
            (f'"{self.target}" jobs "postgresql" OR "mysql" OR "mongodb" OR "redis" OR "kafka"', "jobs_data"),
            (f'"{self.target}" jobs "splunk" OR "datadog" OR "prometheus" OR "grafana"', "jobs_monitoring"),
            (f'"{self.target}" jobs "okta" OR "saml" OR "ldap" OR "active directory"', "jobs_auth"),
        ]

        all_queries = security_queries + job_queries

        for query, label in all_queries:
            hits = self._google_linkedin_search(query, label)
            self.results.extend(hits)
            time.sleep(random.uniform(2, 4))

        # Try direct company page
        company_page = self._fetch_public_company_page()
        self.results.extend(company_page)

        return self.results
