"""
HaveIBeenPwned Collector - checks if the target domain has appeared in data breaches.

Two modes:
1. Domain breach check (no API key needed) — checks which breaches affect the domain
2. Email breach check (requires HIBP API key) — checks specific employee emails

HIBP API key: https://haveibeenpwned.com/API/Key ($3.50/month)
Set via env var: HIBP_API_KEY
"""

import os
import requests
import time
import re


class HIBPCollector:
    def __init__(self, domain: str, api_key: str = None):
        self.domain = domain
        self.api_key = api_key or os.environ.get("HIBP_API_KEY")
        self.base_url = "https://haveibeenpwned.com/api/v3"
        self.results = []

    def _get(self, endpoint: str, params: dict = None) -> dict | list | None:
        headers = {
            "User-Agent": "semantic-recon-security-research",
            "hibp-api-key": self.api_key or "",
        }
        try:
            r = requests.get(f"{self.base_url}{endpoint}", headers=headers,
                             params=params, timeout=10)
            if r.status_code == 404:
                return []   # no breaches found
            if r.status_code == 401:
                return None  # no API key
            if r.status_code == 429:
                time.sleep(2)
                return None
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def collect(self) -> list:
        self._check_domain_breaches()
        if self.api_key:
            self._check_employee_emails()
        else:
            self.results.append({
                "source": "hibp_note",
                "url": "https://haveibeenpwned.com",
                "text": (f"HIBP: No API key provided. Set HIBP_API_KEY to enable per-email breach lookup. "
                         f"Domain-level check attempted for {self.domain}."),
                "date": ""
            })
        return self.results

    def _check_domain_breaches(self):
        """
        Get all breaches and filter for ones that likely include the target domain.
        HIBP doesn't offer a free domain search, so we check all breaches and
        look for industry/sector matches, plus check the domain directly.
        """
        # Check all breaches list (public, no key required)
        try:
            r = requests.get(
                f"{self.base_url}/breaches",
                headers={"User-Agent": "semantic-recon-security-research"},
                timeout=15
            )
            r.raise_for_status()
            all_breaches = r.json()
        except Exception:
            return

        domain_base = self.domain.split(".")[0].lower()

        for breach in all_breaches:
            name = breach.get("Name", "").lower()
            title = breach.get("Title", "")
            breach_domain = breach.get("Domain", "").lower()
            description = breach.get("Description", "")
            pwn_count = breach.get("PwnCount", 0)
            breach_date = breach.get("BreachDate", "")
            data_classes = breach.get("DataClasses", [])
            is_verified = breach.get("IsVerified", False)

            # Direct domain match
            if self.domain.lower() in breach_domain or domain_base in name:
                text = (f"HIBP: Target domain breach found! '{title}' ({breach_date}) — "
                        f"{pwn_count:,} accounts compromised. "
                        f"Data exposed: {', '.join(data_classes)}. "
                        f"Verified: {is_verified}. {description[:200]}")
                self.results.append({
                    "source": "hibp_domain_breach",
                    "url": f"https://haveibeenpwned.com/PwnedWebsites#{breach.get('Name', '')}",
                    "text": text,
                    "date": breach_date
                })

        time.sleep(0.5)

    def _check_employee_emails(self):
        """
        Check specific employee email patterns against HIBP.
        Requires API key. Checks common email formats for the domain.
        Only checks a few pattern-based emails, not brute force.
        """
        # Common email patterns for the domain
        common_prefixes = ["admin", "info", "support", "security", "webmaster",
                           "contact", "noreply", "it", "hr", "dev"]
        emails_to_check = [f"{p}@{self.domain}" for p in common_prefixes]

        for email in emails_to_check:
            data = self._get(f"/breachedaccount/{email}", params={"truncateResponse": "false"})
            if data is None:
                continue  # API error or no key

            if isinstance(data, list) and data:
                breach_names = [b.get("Name", "") for b in data]
                data_classes = list({dc for b in data for dc in b.get("DataClasses", [])})
                text = (f"HIBP: Email {email} found in {len(data)} breach(es): "
                        f"{', '.join(breach_names[:5])}. "
                        f"Data types exposed: {', '.join(data_classes[:8])}.")
                self.results.append({
                    "source": "hibp_email_breach",
                    "url": f"https://haveibeenpwned.com/account/{email}",
                    "text": text,
                    "date": ""
                })
            time.sleep(1.6)  # HIBP rate limit: 1 request per 1.5 seconds

    def extract_emails_from_data(self, raw_data: list) -> list:
        """
        Extract email addresses found in previously collected data
        and check them against HIBP. Call this after other collectors run.
        """
        if not self.api_key:
            return self.results

        email_pattern = re.compile(
            rf'\b[a-zA-Z0-9._%+-]+@{re.escape(self.domain)}\b'
        )

        found_emails = set()
        for item in raw_data:
            text = item.get("text", "")
            matches = email_pattern.findall(text)
            found_emails.update(matches)

        for email in list(found_emails)[:20]:  # cap at 20
            data = self._get(f"/breachedaccount/{email}", params={"truncateResponse": "false"})
            if not data:
                time.sleep(1.6)
                continue

            if isinstance(data, list) and data:
                breach_names = [b.get("Name", "") for b in data]
                data_classes = list({dc for b in data for dc in b.get("DataClasses", [])})
                text = (f"HIBP: Employee email {email} found in {len(data)} breach(es): "
                        f"{', '.join(breach_names[:5])}. "
                        f"Exposed data types: {', '.join(data_classes[:8])}. "
                        f"This email was found in collected OSINT data.")
                self.results.append({
                    "source": "hibp_employee_email",
                    "url": f"https://haveibeenpwned.com/account/{email}",
                    "text": text,
                    "date": ""
                })
            time.sleep(1.6)

        return self.results
