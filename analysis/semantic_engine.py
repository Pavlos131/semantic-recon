"""
Semantic Engine - uses Claude to analyze collected data and produce structured findings
"""

import os
import json
import requests
from dataclasses import dataclass, field
from typing import List

try:
    import anthropic
    HAS_ANTHROPIC = True
except ImportError:
    HAS_ANTHROPIC = False


@dataclass
class Finding:
    category: str
    title: str
    description: str
    confidence: str  # HIGH / MEDIUM / LOW
    inference_chain: str
    evidence_sources: List[str]
    attack_relevance: str
    cves_or_techniques: List[str] = field(default_factory=list)


@dataclass
class ReconReport:
    target: str
    domain: str
    tech_stack: List[Finding]
    internal_tools: List[Finding]
    employee_intel: List[Finding]
    security_posture: List[Finding]
    attack_surface: List[Finding]
    exposed_assets: List[Finding]
    temporal_insights: List[Finding]
    summary: str
    security_maturity_score: int  # 0-10 (0 = very low maturity)


SYSTEM_PROMPT = """You are a senior penetration tester and OSINT analyst performing authorized reconnaissance on a target organization. Your job is to analyze raw collected data from multiple sources (GitHub, Google, Wayback Machine, LinkedIn) and extract structured intelligence.

You think like an attacker: you look for implied information, not just explicit facts. You make inferences based on indirect signals (e.g., job postings reveal tech stack, old robots.txt reveals internal paths, commit messages reveal internal tools).

For each finding you must:
1. State what you found
2. Explain your inference chain (why you concluded this from the evidence)
3. Rate confidence: HIGH (multiple corroborating sources), MEDIUM (one good source), LOW (inference/speculation)
4. Explain attack relevance (what could an attacker do with this)
5. List relevant CVEs, MITRE techniques, or attack approaches

Be precise and technical. This is for an authorized red team engagement."""


ANALYSIS_PROMPT = """Analyze the following raw OSINT data collected about {target} ({domain}).

RAW DATA:
{raw_data}

Produce a comprehensive structured analysis. Return ONLY valid JSON with this exact structure:

{{
  "tech_stack": [
    {{
      "category": "tech_stack",
      "title": "string",
      "description": "string",
      "confidence": "HIGH|MEDIUM|LOW",
      "inference_chain": "step by step reasoning",
      "evidence_sources": ["source1", "source2"],
      "attack_relevance": "string",
      "cves_or_techniques": ["CVE-XXXX-XXXX", "T1234"]
    }}
  ],
  "internal_tools": [...same structure...],
  "employee_intel": [...same structure...],
  "security_posture": [...same structure...],
  "attack_surface": [...same structure...],
  "exposed_assets": [...same structure...],
  "temporal_insights": [...same structure...],
  "summary": "2-3 sentence executive summary of the attack surface",
  "security_maturity_score": 0
}}

Categories:
- tech_stack: Technologies, frameworks, languages, databases inferred from any source
- internal_tools: Internal platforms, CI/CD, monitoring, auth systems
- employee_intel: Key employees, their roles, responsibilities, potential phishing targets
- security_posture: Signs of security maturity or lack thereof
- attack_surface: Specific entry points, vulnerabilities, misconfigurations
- exposed_assets: Files, endpoints, services historically or currently exposed
- temporal_insights: Things that changed over time (migrations, deprecated tech still in use)

Security maturity score: 0-10 where 0 = no visible security practices, 10 = very mature security team.

Be specific with CVEs when you identify a specific technology version. Use MITRE ATT&CK technique IDs when relevant.
Return ONLY the JSON, no markdown, no explanation."""


class SemanticEngine:
    def __init__(self, api_key: str = None, llm: str = "anthropic",
                 ollama_model: str = "llama3", ollama_url: str = "http://localhost:11434"):
        self.llm = llm
        self.ollama_model = ollama_model
        self.ollama_url = ollama_url.rstrip("/")

        if llm == "anthropic":
            key = api_key or os.environ.get("ANTHROPIC_API_KEY")
            if not key:
                raise ValueError("Anthropic API key required. Set ANTHROPIC_API_KEY env var or pass --anthropic-key")
            if not HAS_ANTHROPIC:
                raise ImportError("anthropic package not installed. Run: pip install anthropic")
            self.client = anthropic.Anthropic(api_key=key)
        else:
            self.client = None

    def _chunk_data(self, data: list, max_chars: int = 80000) -> list:
        """Split data into chunks that fit in context"""
        chunks = []
        current_chunk = []
        current_size = 0

        for item in data:
            text = item.get("text", "")
            source = item.get("source", "")
            url = item.get("url", "")
            date = item.get("date", "")

            entry = f"[{source}] ({date}) {text}\nURL: {url}\n---\n"
            entry_size = len(entry)

            if current_size + entry_size > max_chars and current_chunk:
                chunks.append(current_chunk)
                current_chunk = [item]
                current_size = entry_size
            else:
                current_chunk.append(item)
                current_size += entry_size

        if current_chunk:
            chunks.append(current_chunk)

        return chunks

    def _format_chunk(self, chunk: list) -> str:
        lines = []
        for item in chunk:
            lines.append(f"[{item.get('source', 'unknown')}] ({item.get('date', 'unknown date')})")
            lines.append(item.get("text", ""))
            if item.get("url"):
                lines.append(f"URL: {item['url']}")
            lines.append("---")
        return "\n".join(lines)

    def _parse_response(self, response_text: str) -> dict:
        """Parse Claude's JSON response safely"""
        text = response_text.strip()

        # Strip markdown code blocks if present
        if text.startswith("```"):
            text = text.split("```")[1]
            if text.startswith("json"):
                text = text[4:]

        # Extract JSON object boundaries
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            text = text[start:end]

        # Try direct parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Claude sometimes puts literal newlines inside string values (invalid JSON).
        # Replace all unescaped literal newlines/tabs with a space — safe because:
        # - Structural whitespace: space is equivalent
        # - String values: literal newlines are invalid JSON anyway
        import re
        cleaned = re.sub(r'(?<!\\)\n', ' ', text)
        cleaned = re.sub(r'(?<!\\)\r', ' ', cleaned)
        cleaned = re.sub(r'(?<!\\)\t', ' ', cleaned)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        print(f"[DEBUG] All parse attempts failed. Raw response (first 800 chars):\n{response_text[:800]}")
        return {}

    def _findings_from_list(self, raw_list: list, category: str) -> List[Finding]:
        findings = []
        for item in raw_list:
            if not isinstance(item, dict):
                continue
            findings.append(Finding(
                category=item.get("category", category),
                title=item.get("title", "Untitled"),
                description=item.get("description", ""),
                confidence=item.get("confidence", "LOW"),
                inference_chain=item.get("inference_chain", ""),
                evidence_sources=item.get("evidence_sources", []),
                attack_relevance=item.get("attack_relevance", ""),
                cves_or_techniques=item.get("cves_or_techniques", [])
            ))
        return findings

    def _call_ollama(self, prompt: str) -> str:
        """Call local Ollama instance"""
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "stream": False,
            "options": {"num_predict": 4096}
        }
        try:
            r = requests.post(f"{self.ollama_url}/api/chat", json=payload, timeout=300)
            r.raise_for_status()
            return r.json()["message"]["content"]
        except requests.exceptions.ConnectionError:
            raise RuntimeError(
                f"Cannot connect to Ollama at {self.ollama_url}. "
                "Make sure Ollama is running: ollama serve"
            )
        except Exception as e:
            raise RuntimeError(f"Ollama error: {e}")

    def analyze(self, target: str, domain: str, raw_data: list) -> ReconReport:
        """Main analysis function"""
        max_chars = 6000 if self.llm == "ollama" else 30000
        chunks = self._chunk_data(raw_data, max_chars=max_chars)

        # If multiple chunks, analyze each and merge
        all_results = {
            "tech_stack": [], "internal_tools": [], "employee_intel": [],
            "security_posture": [], "attack_surface": [], "exposed_assets": [],
            "temporal_insights": [], "summary": "", "security_maturity_score": 5
        }

        for i, chunk in enumerate(chunks):
            formatted = self._format_chunk(chunk)
            prompt = ANALYSIS_PROMPT.format(
                target=target,
                domain=domain,
                raw_data=formatted
            )

            if self.llm == "anthropic":
                response = self.client.messages.create(
                    model="claude-sonnet-4-6",
                    max_tokens=16000,
                    system=SYSTEM_PROMPT,
                    messages=[{"role": "user", "content": prompt}]
                )
                response_text = response.content[0].text
                if response.stop_reason == "max_tokens":
                    print(f"[WARN] Response truncated (max_tokens). Try reducing --sources or data volume.")
            else:
                response_text = self._call_ollama(prompt)

            result = self._parse_response(response_text)

            # Merge results
            for key in ["tech_stack", "internal_tools", "employee_intel",
                        "security_posture", "attack_surface", "exposed_assets", "temporal_insights"]:
                all_results[key].extend(result.get(key, []))

            # Take the last summary (most complete)
            if result.get("summary"):
                all_results["summary"] = result["summary"]
            if result.get("security_maturity_score") is not None:
                all_results["security_maturity_score"] = result["security_maturity_score"]

        # Deduplicate by title
        for key in ["tech_stack", "internal_tools", "employee_intel",
                    "security_posture", "attack_surface", "exposed_assets", "temporal_insights"]:
            seen = set()
            deduped = []
            for item in all_results[key]:
                title = item.get("title", "") if isinstance(item, dict) else ""
                if title not in seen:
                    seen.add(title)
                    deduped.append(item)
            all_results[key] = deduped

        return ReconReport(
            target=target,
            domain=domain,
            tech_stack=self._findings_from_list(all_results["tech_stack"], "tech_stack"),
            internal_tools=self._findings_from_list(all_results["internal_tools"], "internal_tools"),
            employee_intel=self._findings_from_list(all_results["employee_intel"], "employee_intel"),
            security_posture=self._findings_from_list(all_results["security_posture"], "security_posture"),
            attack_surface=self._findings_from_list(all_results["attack_surface"], "attack_surface"),
            exposed_assets=self._findings_from_list(all_results["exposed_assets"], "exposed_assets"),
            temporal_insights=self._findings_from_list(all_results["temporal_insights"], "temporal_insights"),
            summary=all_results["summary"],
            security_maturity_score=all_results["security_maturity_score"]
        )
