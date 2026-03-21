"""
GitHub Collector - collects repos, commits, issues, job hints from GitHub
"""

import requests
import time
from datetime import datetime, timedelta


class GitHubCollector:
    def __init__(self, target: str, domain: str, token: str = None):
        self.target = target
        self.domain = domain
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
            r.raise_for_status()
            return r.json()
        except Exception:
            return None

    def collect(self) -> list:
        self._search_repos()
        self._search_commits()
        self._search_code()
        self._search_issues()
        return self.results

    def _search_repos(self):
        """Find repos related to the target org/company"""
        queries = [
            f"org:{self.target.lower().replace(' ', '')}",
            f'"{self.target}" in:description',
            f'"{self.domain}" in:readme',
        ]
        for q in queries:
            data = self._get(f"{self.base_url}/search/repositories", params={"q": q, "per_page": 10, "sort": "updated"})
            if not data:
                continue
            for repo in data.get("items", []):
                text = f"Repository: {repo['full_name']} | Description: {repo.get('description', '')} | Language: {repo.get('language', 'unknown')} | Stars: {repo.get('stargazers_count', 0)} | Last updated: {repo.get('updated_at', '')[:10]} | Topics: {', '.join(repo.get('topics', []))}"
                self.results.append({
                    "source": "github_repos",
                    "url": repo.get("html_url", ""),
                    "text": text,
                    "date": repo.get("updated_at", "")[:10]
                })
            time.sleep(0.5)

    def _search_commits(self):
        """Find commits mentioning the domain or company"""
        queries = [
            f'"{self.domain}" committer-date:>{(datetime.now() - timedelta(days=365*2)).strftime("%Y-%m-%d")}',
        ]
        for q in queries:
            data = self._get(f"{self.base_url}/search/commits", params={"q": q, "per_page": 10})
            if not data:
                continue
            for commit in data.get("items", []):
                msg = commit.get("commit", {}).get("message", "")[:300]
                author = commit.get("commit", {}).get("author", {}).get("name", "")
                text = f"Commit by {author}: {msg} | Repo: {commit.get('repository', {}).get('full_name', '')}"
                self.results.append({
                    "source": "github_commits",
                    "url": commit.get("html_url", ""),
                    "text": text,
                    "date": commit.get("commit", {}).get("author", {}).get("date", "")[:10]
                })
            time.sleep(0.5)

    def _search_code(self):
        """Search code for internal configs, endpoints, tech hints"""
        queries = [
            f'"{self.domain}" filename:.env',
            f'"{self.domain}" filename:docker-compose.yml',
            f'"{self.domain}" filename:Jenkinsfile',
            f'"{self.domain}" filename:.github',
        ]
        for q in queries:
            data = self._get(f"{self.base_url}/search/code", params={"q": q, "per_page": 5})
            if not data:
                continue
            for item in data.get("items", []):
                text = f"Code file: {item.get('name', '')} in {item.get('repository', {}).get('full_name', '')} | Path: {item.get('path', '')}"
                self.results.append({
                    "source": "github_code",
                    "url": item.get("html_url", ""),
                    "text": text,
                    "date": ""
                })
            time.sleep(1)

    def _search_issues(self):
        """Find issues/discussions mentioning target"""
        data = self._get(
            f"{self.base_url}/search/issues",
            params={"q": f'"{self.domain}" is:issue', "per_page": 10, "sort": "updated"}
        )
        if not data:
            return
        for issue in data.get("items", []):
            body = (issue.get("body") or "")[:300]
            text = f"Issue: {issue.get('title', '')} | Body: {body} | Repo: {issue.get('repository_url', '').split('repos/')[-1]}"
            self.results.append({
                "source": "github_issues",
                "url": issue.get("html_url", ""),
                "text": text,
                "date": issue.get("updated_at", "")[:10]
            })
        time.sleep(0.5)
