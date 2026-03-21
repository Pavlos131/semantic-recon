"""
WHOIS Collector - gathers current and historical WHOIS data for the target domain.

Sources:
- python-whois: current WHOIS record
- SecurityTrails API (free tier): historical WHOIS + DNS history
- RDAP (free, no key): structured domain registration data
"""

import os
import requests
import time


class WHOISCollector:
    def __init__(self, domain: str, securitytrails_key: str = None):
        self.domain = domain
        self.st_key = securitytrails_key or os.environ.get("SECURITYTRAILS_API_KEY")
        self.results = []

    def collect(self) -> list:
        self._current_whois()
        self._rdap_lookup()
        if self.st_key:
            self._securitytrails_whois_history()
            self._securitytrails_dns_history()
        else:
            self.results.append({
                "source": "whois_note",
                "url": "",
                "text": ("WHOIS: Set SECURITYTRAILS_API_KEY for historical WHOIS and DNS change history. "
                         "Free tier: 50 queries/month at securitytrails.com."),
                "date": ""
            })
        return self.results

    def _current_whois(self):
        """Get current WHOIS data using python-whois."""
        try:
            import whois
            w = whois.whois(self.domain)

            registrar = w.registrar or "unknown"
            creation = str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date or "")[:10]
            expiration = str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date or "")[:10]
            updated = str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date or "")[:10]
            name_servers = w.name_servers or []
            if isinstance(name_servers, list):
                name_servers = [ns.lower() for ns in name_servers]
            emails = w.emails or []
            if isinstance(emails, str):
                emails = [emails]
            org = w.org or w.registrant_name or "unknown"
            country = w.country or "unknown"
            status = w.status or []
            if isinstance(status, str):
                status = [status]

            text = (
                f"WHOIS for {self.domain}: "
                f"Registrar: {registrar} | "
                f"Registrant org: {org} | "
                f"Country: {country} | "
                f"Created: {creation} | "
                f"Expires: {expiration} | "
                f"Updated: {updated} | "
                f"Name servers: {', '.join(name_servers[:4])} | "
                f"Contact emails: {', '.join(emails[:3])} | "
                f"Status: {', '.join(str(s) for s in status[:3])}"
            )
            self.results.append({
                "source": "whois_current",
                "url": f"https://who.is/whois/{self.domain}",
                "text": text,
                "date": updated or creation
            })
        except ImportError:
            self.results.append({
                "source": "whois_note",
                "url": "",
                "text": "python-whois not installed. Run: pip install python-whois",
                "date": ""
            })
        except Exception as e:
            self.results.append({
                "source": "whois_current",
                "url": f"https://who.is/whois/{self.domain}",
                "text": f"WHOIS lookup for {self.domain} failed: {e}",
                "date": ""
            })

    def _rdap_lookup(self):
        """RDAP — modern replacement for WHOIS, structured JSON, no key needed."""
        try:
            r = requests.get(
                f"https://rdap.verisign.com/com/v1/domain/{self.domain}",
                timeout=10
            )
            if r.status_code != 200:
                # Try generic RDAP bootstrap
                r = requests.get(
                    f"https://rdap.org/domain/{self.domain}",
                    timeout=10
                )
            if r.status_code != 200:
                return

            data = r.json()
            events = {e["eventAction"]: e["eventDate"][:10]
                      for e in data.get("events", [])
                      if "eventDate" in e}
            entities = data.get("entities", [])
            registrar_name = ""
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [None, []])[1]
                    for field in vcard:
                        if field[0] == "fn":
                            registrar_name = field[3]
                            break

            status = data.get("status", [])
            text = (
                f"RDAP for {self.domain}: "
                f"Registrar: {registrar_name or 'unknown'} | "
                f"Registered: {events.get('registration', 'unknown')} | "
                f"Last changed: {events.get('last changed', 'unknown')} | "
                f"Expiry: {events.get('expiration', 'unknown')} | "
                f"Status flags: {', '.join(status[:5])}"
            )
            self.results.append({
                "source": "rdap",
                "url": f"https://rdap.org/domain/{self.domain}",
                "text": text,
                "date": events.get("last changed", "")
            })
        except Exception:
            pass

    def _securitytrails_whois_history(self):
        """Historical WHOIS changes via SecurityTrails API."""
        headers = {"APIKEY": self.st_key}
        try:
            r = requests.get(
                f"https://api.securitytrails.com/v1/history/{self.domain}/whois",
                headers=headers,
                timeout=10
            )
            if r.status_code != 200:
                return

            data = r.json()
            records = data.get("result", {}).get("items", [])

            for record in records[:10]:
                date = record.get("date", "")
                registrar = record.get("registrar", {}).get("name", "unknown")
                contacts = record.get("contacts", [])
                emails = [c.get("email", "") for c in contacts if c.get("email")]
                org = next((c.get("organization", "") for c in contacts if c.get("organization")), "")

                text = (
                    f"Historical WHOIS ({date}): "
                    f"Registrar: {registrar} | "
                    f"Organization: {org or 'unknown'} | "
                    f"Contact emails: {', '.join(emails[:3])}"
                )
                self.results.append({
                    "source": "whois_history",
                    "url": f"https://securitytrails.com/domain/{self.domain}/history/whois",
                    "text": text,
                    "date": date
                })
            time.sleep(0.5)
        except Exception:
            pass

    def _securitytrails_dns_history(self):
        """DNS record change history — reveals infrastructure changes over time."""
        headers = {"APIKEY": self.st_key}
        record_types = ["a", "mx", "ns", "txt"]

        for rtype in record_types:
            try:
                r = requests.get(
                    f"https://api.securitytrails.com/v1/history/{self.domain}/dns/{rtype}",
                    headers=headers,
                    timeout=10
                )
                if r.status_code != 200:
                    time.sleep(0.5)
                    continue

                data = r.json()
                records = data.get("records", [])

                for rec in records[:5]:
                    values = rec.get("values", [])
                    first_seen = rec.get("first_seen", "")
                    last_seen = rec.get("last_seen", "")
                    val_strs = []
                    for v in values[:3]:
                        if rtype == "a":
                            val_strs.append(v.get("ip", ""))
                        elif rtype == "mx":
                            val_strs.append(v.get("hostname", ""))
                        elif rtype == "ns":
                            val_strs.append(v.get("nameserver", ""))
                        elif rtype == "txt":
                            val_strs.append(v.get("value", "")[:100])

                    text = (
                        f"DNS history ({rtype.upper()} record): "
                        f"Values: {', '.join(val_strs)} | "
                        f"First seen: {first_seen} | Last seen: {last_seen}"
                    )
                    self.results.append({
                        "source": f"dns_history_{rtype}",
                        "url": f"https://securitytrails.com/domain/{self.domain}/history/{rtype}",
                        "text": text,
                        "date": last_seen
                    })

                time.sleep(0.5)
            except Exception:
                continue
