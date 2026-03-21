"""
GitHub Secrets Collector - searches for leaked credentials, tokens, API keys in public repos
"""

import requests
import time
import re


# Patterns that indicate leaked secrets
SECRET_PATTERNS = [
    # Generic high-value patterns
    (r'password\s*=\s*["\'][^"\']{6,}["\']', "hardcoded password"),
    (r'passwd\s*=\s*["\'][^"\']{6,}["\']', "hardcoded password"),
    (r'secret\s*=\s*["\'][^"\']{8,}["\']', "hardcoded secret"),
    (r'api[_-]?key\s*=\s*["\'][^"\']{8,}["\']', "API key"),
    (r'access[_-]?token\s*=\s*["\'][^"\']{8,}["\']', "access token"),
    (r'private[_-]?key\s*=\s*["\'][^"\']{8,}["\']', "private key"),

    # AWS
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
    (r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?[A-Za-z0-9/+=]{40}', "AWS Secret Key"),

    # GitHub
    (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
    (r'github[_-]?token\s*[=:]\s*["\']?[0-9a-zA-Z]{40}', "GitHub Token"),

    # Slack
    (r'xox[baprs]-[0-9a-zA-Z\-]{10,}', "Slack Token"),

    # Google
    (r'AIza[0-9A-Za-z\-_]{35}', "Google API Key"),

    # Private keys
    (r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----', "Private Key"),

    # Database connection strings
    (r'(mongodb|postgres|postgresql|mysql|redis)://[^\s"\'<>]+:[^\s"\'<>@]+@', "Database connection string with credentials"),

    # JWT secrets
    (r'jwt[_-]?secret\s*[=:]\s*["\'][^"\']{8,}["\']', "JWT secret"),
]

# GitHub search queries targeting secrets in files
SECRET_SEARCH_QUERIES = [
    'filename:.env "{domain}"',
    'filename:.env.local "{domain}"',
    'filename:config.yml "{domain}" password',
    'filename:config.json "{domain}" secret',
    'filename:application.properties "{domain}"',
    'filename:database.yml "{domain}"',
    'filename:settings.py "{domain}" SECRET_KEY',
    'filename:wp-config.php "{domain}"',
    'filename:.bash_history "{domain}"',
    'filename:credentials "{domain}"',
    'filename:id_rsa "{domain}"',
    '"{domain}" password filename:.xml',
    '"{domain}" api_key',
    '"{domain}" AWS_SECRET',
    'org:{org} filename:.env',
    'org:{org} password',
    'org:{org} secret_key',
    'org:{org} api_key',
    'org:{org} PRIVATE KEY',
    'org:{org} AWS_ACCESS_KEY',
]


class GitHubSecretsCollector:
    def __init__(self, target: str, domain: str, token: str = None):
        self.target = target
        self.domain = domain
        self.org = target.lower().replace(" ", "").replace(",", "").replace(".", "")
        self.headers = {"Accept": "application/vnd.github.v3+json"}
        if token:
            self.headers["Authorization"] = f"token {token}"
        self.base_url = "https://api.github.com"
        self.results = []

    def _get(self, url, params=None):
        try:
            r = requests.get(url, headers=self.headers, params=params, timeout=10)
            if r.status_code == 403:
                return None  # rate limited
            if r.status_code == 422:
                return None  # invalid query
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def _get_file_content(self, url: str) -> str:
        """Fetch raw file content from GitHub"""
        try:
            r = requests.get(url, headers=self.headers, timeout=10)
            if r.status_code != 200:
                return ""
            return r.text[:3000]
        except Exception:
            return ""

    def collect(self) -> list:
        self._search_secret_files()
        self._search_commit_secrets()
        return self.results

    def _search_secret_files(self):
        """Search for files that commonly contain secrets"""
        queries = [q.format(domain=self.domain, org=self.org) for q in SECRET_SEARCH_QUERIES]

        for q in queries:
            data = self._get(f"{self.base_url}/search/code", params={"q": q, "per_page": 5})
            if not data:
                time.sleep(1)
                continue

            items = data.get("items", [])
            if not items:
                time.sleep(0.5)
                continue

            for item in items:
                file_name = item.get("name", "")
                repo = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                html_url = item.get("html_url", "")
                raw_url = item.get("url", "")  # API url for raw content

                # Try to get actual content to scan for patterns
                content = ""
                if raw_url:
                    file_data = self._get(raw_url)
                    if file_data and isinstance(file_data, dict):
                        import base64
                        encoded = file_data.get("content", "")
                        if encoded:
                            try:
                                content = base64.b64decode(encoded).decode("utf-8", errors="ignore")[:3000]
                            except Exception:
                                pass

                found_secrets = self._scan_content(content) if content else []

                if found_secrets:
                    text = (f"POTENTIAL SECRETS in {repo}/{path}:\n" +
                            "\n".join(f"  [{s[1]}] {s[0][:120]}" for s in found_secrets[:10]))
                else:
                    text = f"Sensitive file found: {file_name} in {repo} (path: {path})"

                self.results.append({
                    "source": "github_secrets",
                    "url": html_url,
                    "text": text,
                    "date": ""
                })

            time.sleep(1.5)  # be respectful of rate limits

    def _search_commit_secrets(self):
        """Search for secrets accidentally committed and later removed"""
        queries = [
            f'"{self.domain}" remove password',
            f'"{self.domain}" delete secret',
            f'"{self.domain}" revoke token',
            f'org:{self.org} accidentally committed',
            f'org:{self.org} remove credentials',
        ]

        for q in queries:
            data = self._get(f"{self.base_url}/search/commits",
                             params={"q": q, "per_page": 5, "sort": "author-date"})
            if not data:
                time.sleep(1)
                continue

            for commit in data.get("items", []):
                msg = commit.get("commit", {}).get("message", "")[:400]
                author = commit.get("commit", {}).get("author", {}).get("name", "")
                repo = commit.get("repository", {}).get("full_name", "")
                date = commit.get("commit", {}).get("author", {}).get("date", "")[:10]

                self.results.append({
                    "source": "github_secrets_commit",
                    "url": commit.get("html_url", ""),
                    "text": f"Commit suggesting credential removal by {author} in {repo}: {msg}",
                    "date": date
                })

            time.sleep(1)

    def _scan_content(self, content: str) -> list:
        """Scan file content for secret patterns, return list of (match, type)"""
        findings = []
        for pattern, secret_type in SECRET_PATTERNS:
            try:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for m in matches[:3]:  # max 3 per pattern
                    findings.append((m if isinstance(m, str) else str(m), secret_type))
            except re.error:
                pass
        return findings
