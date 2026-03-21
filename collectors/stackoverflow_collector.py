"""
Stack Overflow Collector - finds questions from employees revealing internal tools,
architecture decisions, and tech stack via Stack Exchange API
"""

import requests
import time
import html


class StackOverflowCollector:
    def __init__(self, target: str, domain: str):
        self.target = target
        self.domain = domain
        self.api_base = "https://api.stackexchange.com/2.3"
        self.results = []

    def _get(self, endpoint: str, params: dict) -> dict:
        params.setdefault("site", "stackoverflow")
        params.setdefault("pagesize", 10)
        try:
            r = requests.get(f"{self.api_base}{endpoint}", params=params, timeout=10)
            r.raise_for_status()
            data = r.json()
            # Respect backoff
            if data.get("backoff"):
                time.sleep(data["backoff"] + 1)
            return data
        except Exception:
            return {}

    def collect(self) -> list:
        self._search_by_domain()
        self._search_by_company_name()
        self._search_internal_tools()
        return self.results

    def _search_by_domain(self):
        """Find questions that mention the company domain"""
        data = self._get("/search/advanced", {
            "q": self.domain,
            "sort": "relevance",
            "order": "desc",
            "pagesize": 15,
        })

        for item in data.get("items", []):
            title = html.unescape(item.get("title", ""))
            body = html.unescape(item.get("body", "") or "")[:400]
            tags = item.get("tags", [])
            score = item.get("score", 0)
            link = item.get("link", "")
            owner = item.get("owner", {})
            owner_name = owner.get("display_name", "unknown")
            date = item.get("creation_date", 0)
            date_str = self._ts(date)

            text = (f"Stack Overflow question by {owner_name}: '{title}' | "
                    f"tags: {', '.join(tags)} | score: {score} | "
                    f"body excerpt: {body[:300]}")
            self.results.append({
                "source": "stackoverflow_domain",
                "url": link,
                "text": text,
                "date": date_str
            })

        time.sleep(0.5)

    def _search_by_company_name(self):
        """Find questions mentioning the company name — reveals employees asking about internal issues"""
        company_variants = [
            self.target,
            self.target.lower().replace(" ", ""),
        ]

        for variant in company_variants:
            data = self._get("/search/advanced", {
                "q": f'"{variant}"',
                "sort": "relevance",
                "order": "desc",
                "pagesize": 10,
            })

            for item in data.get("items", []):
                title = html.unescape(item.get("title", ""))
                tags = item.get("tags", [])
                score = item.get("score", 0)
                link = item.get("link", "")
                owner = item.get("owner", {})
                owner_name = owner.get("display_name", "unknown")
                date_str = self._ts(item.get("creation_date", 0))
                body = html.unescape(item.get("body", "") or "")[:300]

                text = (f"Stack Overflow question mentioning '{variant}' by {owner_name}: "
                        f"'{title}' | tags: {', '.join(tags)} | score: {score} | "
                        f"excerpt: {body}")
                self.results.append({
                    "source": "stackoverflow_company",
                    "url": link,
                    "text": text,
                    "date": date_str
                })

            time.sleep(0.5)

    def _search_internal_tools(self):
        """
        Search for questions combining company domain with internal tool keywords.
        These often reveal specific versions, configurations, and architecture details.
        """
        # Keywords that indicate internal infrastructure questions
        internal_keywords = [
            ("kubernetes", "k8s"),
            ("jenkins", "CI/CD"),
            ("vault", "secrets management"),
            ("terraform", "infrastructure as code"),
            ("prometheus", "monitoring"),
            ("elasticsearch", "logging/search"),
            ("kafka", "messaging"),
            ("redis", "caching/sessions"),
            ("ldap", "authentication"),
            ("saml", "SSO"),
            ("oauth", "authentication"),
        ]

        # Get the apex domain without TLD for broader matching
        domain_base = self.domain.split(".")[0]

        for tool, category in internal_keywords:
            data = self._get("/search/advanced", {
                "q": f"{domain_base} {tool}",
                "sort": "relevance",
                "order": "desc",
                "pagesize": 5,
            })

            items = data.get("items", [])
            if not items:
                time.sleep(0.3)
                continue

            for item in items:
                title = html.unescape(item.get("title", ""))
                tags = item.get("tags", [])
                score = item.get("score", 0)
                link = item.get("link", "")
                owner_name = item.get("owner", {}).get("display_name", "unknown")
                body = html.unescape(item.get("body", "") or "")[:400]
                date_str = self._ts(item.get("creation_date", 0))

                # Only include if relevant
                relevance = self.domain in body.lower() or domain_base in title.lower() or tool in " ".join(tags)
                if not relevance:
                    continue

                text = (f"Stack Overflow: {category} question possibly from employee ({owner_name}): "
                        f"'{title}' | tags: {', '.join(tags)} | excerpt: {body[:250]}")
                self.results.append({
                    "source": "stackoverflow_internal_tools",
                    "url": link,
                    "text": text,
                    "date": date_str
                })

            time.sleep(0.5)

    def _ts(self, unix_ts: int) -> str:
        """Convert Unix timestamp to YYYY-MM-DD"""
        if not unix_ts:
            return ""
        try:
            from datetime import datetime
            return datetime.utcfromtimestamp(unix_ts).strftime("%Y-%m-%d")
        except Exception:
            return ""
