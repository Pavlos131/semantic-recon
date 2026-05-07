"""
Correlation Engine - builds a knowledge graph from findings and identifies attack paths.
Entities: Person, Technology, Service, Repository, Endpoint
Relations: uses, knows, responsible_for, exposed_by, connects_to
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Tuple

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False


@dataclass
class Entity:
    id: str
    type: str       # person, technology, service, repository, endpoint
    label: str
    metadata: dict = field(default_factory=dict)


@dataclass
class Relation:
    source: str     # entity id
    target: str     # entity id
    relation: str   # uses, knows, responsible_for, exposed_by, connects_to
    confidence: float = 0.5
    evidence: str = ""


@dataclass
class AttackPath:
    nodes: List[str]
    relations: List[str]
    description: str
    risk_score: float


class CorrelationEngine:
    def __init__(self):
        self.entities: Dict[str, Entity] = {}
        self.relations: List[Relation] = []
        if HAS_NETWORKX:
            self.graph = nx.DiGraph()
        else:
            self.graph = None

    def _entity_id(self, label: str, etype: str) -> str:
        return f"{etype}:{label.lower().strip()}"

    def _add_entity(self, label: str, etype: str, metadata: dict = None) -> str:
        eid = self._entity_id(label, etype)
        if eid not in self.entities:
            self.entities[eid] = Entity(id=eid, type=etype, label=label, metadata=metadata or {})
            if self.graph is not None:
                self.graph.add_node(eid, type=etype, label=label)
        return eid

    def _add_relation(self, src: str, tgt: str, rel: str, confidence: float = 0.5, evidence: str = ""):
        self.relations.append(Relation(source=src, target=tgt, relation=rel,
                                       confidence=confidence, evidence=evidence))
        if self.graph is not None:
            self.graph.add_edge(src, tgt, relation=rel, weight=confidence)

    def build_from_findings(self, report) -> None:
        """Extract entities and relations from a ReconReport."""
        # Tech stack
        for f in report.tech_stack:
            tid = self._add_entity(f.title, "technology", {"confidence": f.confidence})
            for cve in f.cves_or_techniques:
                cid = self._add_entity(cve, "vulnerability")
                conf = 0.9 if f.confidence == "HIGH" else 0.5
                self._add_relation(tid, cid, "has_vulnerability", confidence=conf, evidence=f.title)
                # Reverse edge so attack paths can traverse: attack_vector → vuln → technology
                self._add_relation(cid, tid, "affects", confidence=conf, evidence=f.title)

        # Internal tools
        for f in report.internal_tools:
            sid = self._add_entity(f.title, "service", {"confidence": f.confidence})
            # link to tech if mentioned
            for tech_entity in list(self.entities.values()):
                if tech_entity.type == "technology" and tech_entity.label.lower() in f.description.lower():
                    self._add_relation(sid, tech_entity.id, "uses",
                                       confidence=0.6, evidence=f.title)

        # Employee intel
        for f in report.employee_intel:
            persons = _extract_names(f.title + " " + f.description)
            for name in persons:
                pid = self._add_entity(name, "person", {"confidence": f.confidence})
                # link person to services/tech they're responsible for
                for entity in list(self.entities.values()):
                    if entity.type in ("service", "technology"):
                        if entity.label.lower() in f.description.lower():
                            self._add_relation(pid, entity.id, "responsible_for",
                                               confidence=0.7, evidence=f.title)

        # Exposed assets → endpoints
        for f in report.exposed_assets:
            eid = self._add_entity(f.title, "endpoint", {"confidence": f.confidence})
            for cve in f.cves_or_techniques:
                cid = self._add_entity(cve, "vulnerability")
                self._add_relation(eid, cid, "exposed_by", confidence=0.8, evidence=f.title)
                self._add_relation(cid, eid, "found_at", confidence=0.8, evidence=f.title)

        # Attack surface
        for f in report.attack_surface:
            aid = self._add_entity(f.title, "attack_vector", {"confidence": f.confidence})
            for cve in f.cves_or_techniques:
                cid = self._add_entity(cve, "vulnerability")
                self._add_relation(aid, cid, "exploits", confidence=0.8, evidence=f.title)

    def find_attack_paths(self) -> List[AttackPath]:
        """Find high-value attack paths: external → internal assets."""
        if self.graph is None or not HAS_NETWORKX:
            return []

        paths = []
        external_nodes = [n for n, d in self.graph.nodes(data=True)
                          if d.get("type") in ("endpoint", "attack_vector")]
        internal_nodes = [n for n, d in self.graph.nodes(data=True)
                          if d.get("type") in ("service", "technology", "person")]
        vuln_nodes = [n for n, d in self.graph.nodes(data=True)
                      if d.get("type") == "vulnerability"]

        # Paths from external entry points to internal services via vulnerabilities
        for ext in external_nodes:
            for vuln in vuln_nodes:
                if not nx.has_path(self.graph, ext, vuln):
                    continue
                for internal in internal_nodes:
                    if not nx.has_path(self.graph, vuln, internal):
                        continue
                    try:
                        path1 = nx.shortest_path(self.graph, ext, vuln)
                        path2 = nx.shortest_path(self.graph, vuln, internal)
                        full_path = path1 + path2[1:]

                        risk = _calculate_risk(self.graph, full_path)
                        relations = [
                            self.graph[full_path[i]][full_path[i+1]].get("relation", "→")
                            for i in range(len(full_path) - 1)
                        ]
                        labels = [self.entities[n].label for n in full_path if n in self.entities]
                        desc = " → ".join(labels)

                        paths.append(AttackPath(
                            nodes=full_path,
                            relations=relations,
                            description=desc,
                            risk_score=risk
                        ))
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue

        # Fallback: direct paths from attack_vector/endpoint to service/technology
        if not paths:
            for ext in external_nodes:
                for internal in internal_nodes:
                    try:
                        if nx.has_path(self.graph, ext, internal):
                            path = nx.shortest_path(self.graph, ext, internal)
                            risk = _calculate_risk(self.graph, path)
                            relations = [
                                self.graph[path[i]][path[i+1]].get("relation", "→")
                                for i in range(len(path) - 1)
                            ]
                            labels = [self.entities[n].label for n in path if n in self.entities]
                            paths.append(AttackPath(
                                nodes=path,
                                relations=relations,
                                description=" → ".join(labels),
                                risk_score=risk
                            ))
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue

        # Deduplicate and sort by risk
        seen = set()
        unique = []
        for p in sorted(paths, key=lambda x: x.risk_score, reverse=True):
            key = tuple(p.nodes)
            if key not in seen:
                seen.add(key)
                unique.append(p)

        return unique[:10]

    def to_dict(self) -> dict:
        """Serialize graph to dict for use in HTML report."""
        nodes = [
            {"id": e.id, "label": e.label, "type": e.type, **e.metadata}
            for e in self.entities.values()
        ]
        edges = [
            {"source": r.source, "target": r.target, "relation": r.relation,
             "confidence": r.confidence}
            for r in self.relations
        ]
        return {"nodes": nodes, "edges": edges}


def _extract_names(text: str) -> List[str]:
    """Very naive name extraction: capitalized word pairs."""
    pattern = r'\b([A-Z][a-z]+ [A-Z][a-z]+)\b'
    return list(set(re.findall(pattern, text)))[:5]


def _calculate_risk(graph, path: list) -> float:
    """Score a path by average edge confidence."""
    if len(path) < 2:
        return 0.0
    weights = [
        graph[path[i]][path[i+1]].get("weight", 0.5)
        for i in range(len(path) - 1)
    ]
    return sum(weights) / len(weights)
