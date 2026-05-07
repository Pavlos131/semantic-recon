"""
DNS Collector - subdomain enumeration via crt.sh + DNS record analysis
"""

import requests
import time
import socket

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


class DNSCollector:
    def __init__(self, domain: str):
        self.domain = domain
        self.results = []

    def _get(self, url, params=None, timeout=15):
        try:
            r = requests.get(url, params=params, timeout=timeout,
                             headers={"User-Agent": "Mozilla/5.0"})
            r.raise_for_status()
            return r
        except Exception:
            return None

    def collect(self) -> list:
        self._crtsh_subdomains()
        self._hackertarget_subdomains()
        self._rapiddns_subdomains()
        self._dns_records()
        self._check_zone_transfer()
        return self.results

    def _crtsh_subdomains(self):
        """Enumerate subdomains from Certificate Transparency logs via crt.sh"""
        r = self._get("https://crt.sh/", params={"q": f"%.{self.domain}", "output": "json"})
        if not r:
            return

        try:
            entries = r.json()
        except Exception:
            return

        seen = set()
        subdomains = []
        for entry in entries:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub not in seen and self.domain in sub:
                    seen.add(sub)
                    subdomains.append((sub, entry.get("issuer_name", ""), entry.get("not_before", "")))

        if subdomains:
            # Report as one block (too many individual entries clogs context)
            sub_list = "\n".join(f"  - {s[0]} (issuer: {s[1][:40]}, since: {s[2][:10]})"
                                 for s in subdomains[:60])
            self.results.append({
                "source": "dns_crtsh",
                "url": f"https://crt.sh/?q=%.{self.domain}",
                "text": f"Certificate Transparency subdomains for {self.domain} ({len(seen)} unique):\n{sub_list}",
                "date": ""
            })

            # Also resolve each subdomain to find live ones
            live = []
            for sub, _, _ in subdomains[:40]:
                try:
                    ip = socket.gethostbyname(sub)
                    live.append(f"{sub} → {ip}")
                except Exception:
                    pass

            if live:
                self.results.append({
                    "source": "dns_live_subdomains",
                    "url": "",
                    "text": f"Live (resolvable) subdomains ({len(live)}):\n" + "\n".join(f"  - {s}" for s in live),
                    "date": ""
                })

        time.sleep(1)

    def _hackertarget_subdomains(self):
        """Passive subdomain enumeration via HackerTarget API (free, no key needed)"""
        r = self._get(f"https://api.hackertarget.com/hostsearch/?q={self.domain}")
        if not r or "error" in r.text.lower()[:50]:
            return
        lines = [l.strip() for l in r.text.strip().splitlines() if self.domain in l]
        if not lines:
            return
        subs = list({l.split(",")[0] for l in lines if "," in l})[:50]
        if subs:
            self.results.append({
                "source": "dns_hackertarget",
                "url": f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
                "text": f"HackerTarget subdomains for {self.domain} ({len(subs)} found):\n" +
                        "\n".join(f"  - {s}" for s in subs),
                "date": ""
            })
        time.sleep(1)

    def _rapiddns_subdomains(self):
        """Passive subdomain enumeration via RapidDNS (free)"""
        r = self._get(f"https://rapiddns.io/subdomain/{self.domain}?full=1",
                      timeout=10)
        if not r:
            return
        import re
        found = list(set(re.findall(
            rf'[\w\-]+\.{re.escape(self.domain)}', r.text
        )))[:50]
        if found:
            self.results.append({
                "source": "dns_rapiddns",
                "url": f"https://rapiddns.io/subdomain/{self.domain}",
                "text": f"RapidDNS subdomains for {self.domain} ({len(found)} found):\n" +
                        "\n".join(f"  - {s}" for s in found),
                "date": ""
            })
        time.sleep(1)

    def _dns_records(self):
        """Collect MX, TXT (SPF/DMARC), NS, CNAME records"""
        if not HAS_DNSPYTHON:
            self._dns_records_fallback()
            return

        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        record_types = {
            "MX": "Mail servers (reveals email provider, spam filtering stack)",
            "TXT": "TXT records (SPF, DMARC, DKIM, Google/Azure/Slack verification tokens)",
            "NS": "Nameservers (DNS provider)",
            "A": "A records (IPs for root domain)",
            "AAAA": "AAAA records (IPv6)",
        }

        for rtype, description in record_types.items():
            try:
                answers = resolver.resolve(self.domain, rtype)
                values = [str(r) for r in answers]
                text = f"{rtype} records ({description}):\n" + "\n".join(f"  {v}" for v in values)
                self.results.append({
                    "source": "dns_records",
                    "url": "",
                    "text": text,
                    "date": ""
                })

                # Flag SPF/DMARC issues specifically
                if rtype == "TXT":
                    self._analyze_txt_records(values)

            except (dns.exception.DNSException, Exception):
                pass

        # Check DMARC separately
        try:
            answers = resolver.resolve(f"_dmarc.{self.domain}", "TXT")
            values = [str(r) for r in answers]
            text = f"DMARC record: {' '.join(values)}"
            self.results.append({
                "source": "dns_dmarc",
                "url": "",
                "text": text,
                "date": ""
            })
            self._analyze_dmarc(values)
        except Exception:
            self.results.append({
                "source": "dns_dmarc",
                "url": "",
                "text": f"No DMARC record found for {self.domain} — domain is vulnerable to email spoofing",
                "date": ""
            })

    def _dns_records_fallback(self):
        """Fallback when dnspython not installed — use socket for basic A record"""
        try:
            ip = socket.gethostbyname(self.domain)
            self.results.append({
                "source": "dns_records",
                "url": "",
                "text": f"A record: {self.domain} → {ip} (install dnspython for full DNS analysis)",
                "date": ""
            })
        except Exception:
            pass

    def _analyze_txt_records(self, values: list):
        """Flag SPF misconfigurations"""
        spf_records = [v for v in values if "v=spf1" in v]
        if not spf_records:
            self.results.append({
                "source": "dns_security_issue",
                "url": "",
                "text": f"SECURITY: No SPF record found for {self.domain} — domain can be used for email spoofing/phishing",
                "date": ""
            })
            return

        for spf in spf_records:
            if "+all" in spf:
                self.results.append({
                    "source": "dns_security_issue",
                    "url": "",
                    "text": f"CRITICAL: SPF record uses '+all' — any server can send email as {self.domain}: {spf}",
                    "date": ""
                })
            elif "~all" in spf:
                self.results.append({
                    "source": "dns_security_issue",
                    "url": "",
                    "text": f"WEAK SPF: '~all' (softfail) means unauthorized senders are not rejected for {self.domain}: {spf}",
                    "date": ""
                })
            # Extract third-party email services
            services = []
            if "include:_spf.google.com" in spf or "include:google.com" in spf:
                services.append("Google Workspace")
            if "include:spf.protection.outlook.com" in spf or "include:spf.sendinblue.com" in spf:
                services.append("Microsoft 365")
            if "include:sendgrid.net" in spf:
                services.append("SendGrid")
            if "include:amazonses.com" in spf:
                services.append("Amazon SES")
            if "include:mailgun.org" in spf:
                services.append("Mailgun")
            if services:
                self.results.append({
                    "source": "dns_email_providers",
                    "url": "",
                    "text": f"Email providers inferred from SPF: {', '.join(services)}",
                    "date": ""
                })

    def _analyze_dmarc(self, values: list):
        """Flag weak DMARC policies"""
        for v in values:
            v_clean = v.strip('"')
            if "p=none" in v_clean:
                self.results.append({
                    "source": "dns_security_issue",
                    "url": "",
                    "text": f"WEAK DMARC: policy=none means unauthenticated emails are NOT rejected — spoofing risk: {v_clean}",
                    "date": ""
                })
            elif "p=quarantine" in v_clean:
                self.results.append({
                    "source": "dns_security_issue",
                    "url": "",
                    "text": f"MODERATE DMARC: policy=quarantine (spam folder, not rejected): {v_clean}",
                    "date": ""
                })

    def _check_zone_transfer(self):
        """Attempt AXFR zone transfer (almost always fails, but worth logging)"""
        if not HAS_DNSPYTHON:
            return
        try:
            ns_answers = dns.resolver.resolve(self.domain, "NS")
            for ns in ns_answers:
                ns_str = str(ns).rstrip(".")
                try:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_str, self.domain, timeout=3))
                    names = list(zone.nodes.keys())
                    self.results.append({
                        "source": "dns_zone_transfer",
                        "url": "",
                        "text": f"CRITICAL: Zone transfer SUCCEEDED from {ns_str}! Records: {[str(n) for n in names[:30]]}",
                        "date": ""
                    })
                except Exception:
                    pass  # Expected — zone transfers are almost always blocked
        except Exception:
            pass
