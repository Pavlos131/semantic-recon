"""
Wayback Machine Collector - finds historical snapshots and deleted content
"""

import requests
import time
from urllib.parse import urljoin


class WaybackCollector:
    def __init__(self, domain: str):
        self.domain = domain
        self.results = []
        self.cdx_api = "https://web.archive.org/cdx/search/cdx"
        self.availability_api = "https://archive.org/wayback/available"

    def _cdx_query(self, url_pattern: str, limit: int = 20, filters: list = None) -> list:
        """Query the CDX API for snapshots"""
        params = {
            "url": url_pattern,
            "output": "json",
            "limit": limit,
            "fl": "timestamp,original,statuscode,mimetype",
            "collapse": "urlkey",
        }
        if filters:
            params["filter"] = filters

        try:
            r = requests.get(self.cdx_api, params=params, timeout=15)
            r.raise_for_status()
            data = r.json()
            return data[1:] if data else []  # first row is header
        except Exception:
            return []

    def _fetch_snapshot_text(self, timestamp: str, url: str) -> str:
        """Fetch text content from a specific snapshot"""
        snapshot_url = f"https://web.archive.org/web/{timestamp}/{url}"
        try:
            r = requests.get(snapshot_url, timeout=10)
            if r.status_code != 200:
                return ""
            # Strip HTML tags roughly
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            # Remove scripts/styles
            for tag in soup(["script", "style", "nav", "footer"]):
                tag.decompose()
            text = soup.get_text(separator=" ", strip=True)
            return text[:1500]
        except Exception:
            return ""

    def collect(self) -> list:
        self._find_interesting_paths()
        self._find_deleted_pages()
        self._find_old_tech_references()
        self._check_robots_history()
        return self.results

    def _find_interesting_paths(self):
        """Look for historically exposed sensitive paths"""
        sensitive_patterns = [
            f"{self.domain}/.env",
            f"{self.domain}/config*",
            f"{self.domain}/admin*",
            f"{self.domain}/api/v*",
            f"{self.domain}/swagger*",
            f"{self.domain}/graphql*",
            f"{self.domain}/.git*",
            f"{self.domain}/phpinfo*",
            f"{self.domain}/server-status*",
            f"{self.domain}/wp-admin*",
        ]

        for pattern in sensitive_patterns:
            snapshots = self._cdx_query(pattern, limit=5, filters=["statuscode:200"])
            for snap in snapshots:
                if len(snap) < 4:
                    continue
                timestamp, original_url, status, mimetype = snap[0], snap[1], snap[2], snap[3]
                year = timestamp[:4]
                text = f"Historical exposure: {original_url} was accessible in {year} (status {status}, type {mimetype})"
                self.results.append({
                    "source": "wayback_sensitive_path",
                    "url": f"https://web.archive.org/web/{timestamp}/{original_url}",
                    "text": text,
                    "date": f"{year}-{timestamp[4:6]}-{timestamp[6:8]}"
                })
            time.sleep(0.5)

    def _find_deleted_pages(self):
        """Find pages that existed before but are now gone (3xx/4xx now but 200 before)"""
        snapshots = self._cdx_query(f"{self.domain}/*", limit=50)

        seen_urls = set()
        for snap in snapshots:
            if len(snap) < 4:
                continue
            timestamp, url, status, mimetype = snap[0], snap[1], snap[2], snap[3]

            # Look for pages that were accessible
            if status == "200" and url not in seen_urls:
                seen_urls.add(url)

                # Check if interesting path
                keywords = ["internal", "staging", "dev", "test", "beta", "old", "backup",
                           "admin", "portal", "dashboard", "api", "docs", "wiki"]
                if any(kw in url.lower() for kw in keywords):
                    year = timestamp[:4]
                    text = f"Previously accessible page: {url} (last seen {year}). May still exist in deployment."
                    self.results.append({
                        "source": "wayback_deleted_page",
                        "url": f"https://web.archive.org/web/{timestamp}/{url}",
                        "text": text,
                        "date": f"{year}-{timestamp[4:6]}-{timestamp[6:8]}"
                    })

    def _find_old_tech_references(self):
        """Fetch old homepage snapshots to find historical tech stack"""
        snapshots = self._cdx_query(self.domain, limit=10)

        # Sample snapshots from different years
        years_sampled = set()
        for snap in snapshots:
            if len(snap) < 2:
                continue
            timestamp, url = snap[0], snap[1]
            year = timestamp[:4]

            if year not in years_sampled and int(year) >= 2015:
                years_sampled.add(year)
                text = self._fetch_snapshot_text(timestamp, url)

                if text and len(text) > 100:
                    self.results.append({
                        "source": "wayback_historical_content",
                        "url": f"https://web.archive.org/web/{timestamp}/{url}",
                        "text": f"Homepage content from {year}: {text[:800]}",
                        "date": f"{year}-{timestamp[4:6]}-{timestamp[6:8]}"
                    })
                time.sleep(1)

    def _check_robots_history(self):
        """robots.txt history reveals internal paths"""
        snapshots = self._cdx_query(f"{self.domain}/robots.txt", limit=10, filters=["statuscode:200"])

        years_sampled = set()
        for snap in snapshots:
            if len(snap) < 2:
                continue
            timestamp, url = snap[0], snap[1]
            year = timestamp[:4]

            if year not in years_sampled:
                years_sampled.add(year)
                text = self._fetch_snapshot_text(timestamp, url)
                if text:
                    self.results.append({
                        "source": "wayback_robots",
                        "url": f"https://web.archive.org/web/{timestamp}/{url}",
                        "text": f"robots.txt from {year}: {text[:600]}",
                        "date": f"{year}-{timestamp[4:6]}-{timestamp[6:8]}"
                    })
                time.sleep(1)
