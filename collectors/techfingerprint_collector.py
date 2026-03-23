"""
Tech Fingerprinting Collector — HTTP header analysis.
Makes passive, read-only GET requests to safe public paths and extracts
technology signals from response headers and body hints.

NOT included in default sources. Enable with: --sources techfingerprint
or add to config.yaml sources.
"""

import requests
from datetime import datetime

# Safe, read-only paths — no mutation, no auth bypass attempts
PROBE_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/api/",
    "/.well-known/security.txt",
    "/.well-known/change-password",
]

# Headers that reveal technology stack
TECH_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "X-WordPress-Cache",
    "X-Pingback",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Runtime",           # Rails
    "X-Shopify-Stage",
    "X-Discourse-Route",
    "Via",
    "CF-RAY",              # Cloudflare
    "X-Varnish",           # Varnish cache
    "X-Cache",
    "X-Amz-Cf-Id",        # AWS CloudFront
    "X-Amz-Request-Id",
    "X-Fastly-Request-ID",
    "Fly-Request-Id",
    "X-Vercel-Id",
    "X-Netlify-Deployment-Id",
]

# Security-relevant headers (absence is also a finding)
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

# Cookie flags that reveal tech/security posture
COOKIE_SIGNALS = {
    "PHPSESSID": "PHP",
    "JSESSIONID": "Java Servlet (Tomcat/Jetty)",
    "ASP.NET_SessionId": "ASP.NET",
    "laravel_session": "Laravel (PHP)",
    "wordpress_": "WordPress",
    "wp-settings-": "WordPress",
    "django": "Django (Python)",
    "csrftoken": "Django/Python CSRF",
    "_rails_": "Ruby on Rails",
    "connect.sid": "Node.js (Express/Connect)",
    "AWSALB": "AWS ALB",
    "AWSELB": "AWS ELB",
}


class TechFingerprintCollector:
    def __init__(self, domain: str, timeout: int = 8, https: bool = True):
        self.domain = domain
        self.timeout = timeout
        self.scheme = "https" if https else "http"
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; reconnaissance/1.0; +https://example.com/bot)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        })

    def _probe(self, path: str) -> dict | None:
        url = f"{self.scheme}://{self.domain}{path}"
        try:
            r = self.session.get(url, timeout=self.timeout, allow_redirects=True,
                                 verify=False)
            return {
                "url": r.url,
                "status": r.status_code,
                "headers": dict(r.headers),
                "cookies": {c.name: {"value": c.value[:60], "secure": c.secure,
                                     "httponly": c.has_nonstandard_attr("HttpOnly") or c.secure,
                                     "samesite": c.get_nonstandard_attr("SameSite", "Not set")}
                            for c in r.cookies},
                "body_snippet": r.text[:500] if r.status_code == 200 else "",
            }
        except requests.exceptions.SSLError:
            # Retry without TLS
            try:
                r = self.session.get(f"http://{self.domain}{path}", timeout=self.timeout,
                                     allow_redirects=True)
                return {"url": r.url, "status": r.status_code,
                        "headers": dict(r.headers), "cookies": {},
                        "body_snippet": r.text[:500] if r.status_code == 200 else "",
                        "ssl_error": True}
            except Exception:
                return None
        except Exception:
            return None

    def _extract_signals(self, path: str, probe: dict) -> list:
        """Turn a raw probe result into structured data points."""
        points = []
        headers = {k.lower(): v for k, v in probe["headers"].items()}
        now = datetime.utcnow().strftime("%Y-%m-%d")

        # --- Tech headers ---
        tech_hits = {}
        for h in TECH_HEADERS:
            val = headers.get(h.lower())
            if val:
                tech_hits[h] = val

        if tech_hits:
            lines = [f"{h}: {v}" for h, v in tech_hits.items()]
            points.append({
                "source": "techfingerprint",
                "url": probe["url"],
                "date": now,
                "text": (
                    f"HTTP headers from {probe['url']} reveal technology signals:\n"
                    + "\n".join(lines)
                ),
            })

        # --- Security header audit ---
        present = [h for h in SECURITY_HEADERS if h.lower() in headers]
        missing = [h for h in SECURITY_HEADERS if h.lower() not in headers]
        if missing:
            points.append({
                "source": "techfingerprint",
                "url": probe["url"],
                "date": now,
                "text": (
                    f"Security header audit for {probe['url']}:\n"
                    f"  Present ({len(present)}): {', '.join(present) or 'none'}\n"
                    f"  Missing ({len(missing)}): {', '.join(missing)}"
                ),
            })

        # --- Cookie analysis ---
        for name, meta in probe.get("cookies", {}).items():
            matched_tech = next(
                (tech for sig, tech in COOKIE_SIGNALS.items() if sig.lower() in name.lower()),
                None
            )
            flags = []
            if not meta.get("secure"):
                flags.append("Secure flag MISSING")
            if not meta.get("httponly"):
                flags.append("HttpOnly flag MISSING")
            if meta.get("samesite", "Not set") == "Not set":
                flags.append("SameSite not set")

            cookie_text = f"Cookie '{name}' set by {probe['url']}"
            if matched_tech:
                cookie_text += f" — indicates {matched_tech}"
            if flags:
                cookie_text += f". Security issues: {', '.join(flags)}"

            points.append({
                "source": "techfingerprint",
                "url": probe["url"],
                "date": now,
                "text": cookie_text,
            })

        # --- Cloudflare detection ---
        if "cf-ray" in headers:
            points.append({
                "source": "techfingerprint",
                "url": probe["url"],
                "date": now,
                "text": f"Cloudflare CDN detected on {self.domain} (CF-RAY header present). "
                        f"Real origin IP may be obscured. WAF likely in place.",
            })

        # --- SSL error ---
        if probe.get("ssl_error"):
            points.append({
                "source": "techfingerprint",
                "url": probe["url"],
                "date": now,
                "text": f"SSL/TLS handshake failed for https://{self.domain}{path}. "
                        f"Site may not support HTTPS or has certificate misconfiguration.",
            })

        # --- robots.txt content ---
        if path == "/robots.txt" and probe["status"] == 200 and probe.get("body_snippet"):
            points.append({
                "source": "techfingerprint",
                "url": probe["url"],
                "date": now,
                "text": f"robots.txt content from {probe['url']}:\n{probe['body_snippet']}",
            })

        # --- security.txt content ---
        if "security.txt" in path and probe["status"] == 200 and probe.get("body_snippet"):
            points.append({
                "source": "techfingerprint",
                "url": probe["url"],
                "date": now,
                "text": f"security.txt found at {probe['url']}:\n{probe['body_snippet']}",
            })

        return points

    def collect(self) -> list:
        import warnings
        import urllib3
        warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

        results = []
        for path in PROBE_PATHS:
            probe = self._probe(path)
            if probe:
                results.extend(self._extract_signals(path, probe))

        return results
