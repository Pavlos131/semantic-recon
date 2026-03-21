"""
Shodan Collector - open ports, banners, software versions, known CVEs
Requires SHODAN_API_KEY env var or shodan_key constructor param
"""

import os
import time

try:
    import shodan
    HAS_SHODAN = True
except ImportError:
    HAS_SHODAN = False


class ShodanCollector:
    def __init__(self, domain: str, api_key: str = None):
        self.domain = domain
        self.api_key = api_key or os.environ.get("SHODAN_API_KEY")
        self.results = []

    def collect(self) -> list:
        if not HAS_SHODAN:
            self.results.append({
                "source": "shodan",
                "url": "",
                "text": "Shodan library not installed. Run: pip install shodan",
                "date": ""
            })
            return self.results

        if not self.api_key:
            self.results.append({
                "source": "shodan",
                "url": "",
                "text": "No Shodan API key. Set SHODAN_API_KEY env var to enable Shodan collection.",
                "date": ""
            })
            return self.results

        api = shodan.Shodan(self.api_key)
        self._search_by_hostname(api)
        self._search_ssl_cert(api)
        return self.results

    def _search_by_hostname(self, api):
        """Search Shodan for hosts associated with the domain"""
        try:
            results = api.search(f"hostname:{self.domain}", limit=50)
            total = results.get("total", 0)

            if total == 0:
                return

            hosts_summary = []
            for host in results.get("matches", []):
                ip = host.get("ip_str", "")
                port = host.get("port", "")
                transport = host.get("transport", "tcp")
                product = host.get("product", "")
                version = host.get("version", "")
                hostnames = ", ".join(host.get("hostnames", []))
                org = host.get("org", "")
                os_info = host.get("os", "")
                banner = (host.get("data", "") or "")[:200]
                vulns = list(host.get("vulns", {}).keys())
                timestamp = host.get("timestamp", "")[:10]

                # Build readable summary
                parts = [f"Host: {ip}:{port}/{transport}"]
                if hostnames:
                    parts.append(f"hostnames: {hostnames}")
                if product:
                    parts.append(f"software: {product} {version}".strip())
                if os_info:
                    parts.append(f"OS: {os_info}")
                if org:
                    parts.append(f"org: {org}")
                if vulns:
                    parts.append(f"KNOWN CVEs: {', '.join(vulns)}")
                if banner:
                    parts.append(f"banner: {banner}")

                entry = " | ".join(parts)
                hosts_summary.append(entry)

                # Emit critical vuln hosts immediately as separate findings
                if vulns:
                    self.results.append({
                        "source": "shodan_vulns",
                        "url": f"https://www.shodan.io/host/{ip}",
                        "text": f"VULNERABLE HOST: {ip}:{port} running {product} {version} — CVEs: {', '.join(vulns)}",
                        "date": timestamp
                    })

            if hosts_summary:
                self.results.append({
                    "source": "shodan_hosts",
                    "url": f"https://www.shodan.io/search?query=hostname:{self.domain}",
                    "text": f"Shodan found {total} results for hostname:{self.domain}:\n" +
                            "\n".join(f"  - {e}" for e in hosts_summary[:30]),
                    "date": ""
                })

            time.sleep(1)

        except shodan.APIError as e:
            self.results.append({
                "source": "shodan",
                "url": "",
                "text": f"Shodan API error: {e}",
                "date": ""
            })

    def _search_ssl_cert(self, api):
        """Search by SSL certificate CN to find hosts not directly in hostname results"""
        try:
            results = api.search(f'ssl.cert.subject.cn:"{self.domain}"', limit=20)
            total = results.get("total", 0)

            if total == 0:
                return

            entries = []
            for host in results.get("matches", []):
                ip = host.get("ip_str", "")
                port = host.get("port", "")
                product = host.get("product", "")
                version = host.get("version", "")
                org = host.get("org", "")
                vulns = list(host.get("vulns", {}).keys())
                timestamp = host.get("timestamp", "")[:10]

                parts = [f"{ip}:{port}"]
                if product:
                    parts.append(f"{product} {version}".strip())
                if org:
                    parts.append(f"org: {org}")
                if vulns:
                    parts.append(f"CVEs: {', '.join(vulns)}")

                entries.append(" | ".join(parts))

                if vulns:
                    self.results.append({
                        "source": "shodan_vulns",
                        "url": f"https://www.shodan.io/host/{ip}",
                        "text": f"VULNERABLE HOST (SSL cert): {ip}:{port} {product} {version} — CVEs: {', '.join(vulns)}",
                        "date": timestamp
                    })

            if entries:
                self.results.append({
                    "source": "shodan_ssl",
                    "url": f"https://www.shodan.io/search?query=ssl.cert.subject.cn:{self.domain}",
                    "text": f"Shodan SSL cert search found {total} additional hosts with cert CN matching {self.domain}:\n" +
                            "\n".join(f"  - {e}" for e in entries[:20]),
                    "date": ""
                })

            time.sleep(1)

        except shodan.APIError:
            pass
