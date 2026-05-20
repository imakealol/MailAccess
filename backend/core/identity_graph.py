from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

_USERNAME_KEYS = frozenset({"username", "login", "user", "handle", "matched_username"})
_DISPLAY_KEYS = frozenset({"display_name", "name", "full_name", "real_name"})
_PHOTO_KEYS = frozenset({
    "photo_url",
    "thumbnail_url",
    "avatar_url",
    "profile_photo",
    "image_url",
})
_BREACH_MODULES = frozenset({"hibp", "breachdirectory", "haveibeenpwned"})


def _node_id(node_type: str, value: str) -> str:
    digest = hashlib.sha256(f"{node_type}:{value}".encode()).hexdigest()[:12]
    return f"{node_type}_{digest}"


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)
    degree: int = 0
    high_confidence_node: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "value": self.value,
            "metadata": self.metadata,
            "degree": self.degree,
            "high_confidence_node": self.high_confidence_node,
        }


@dataclass
class GraphEdge:
    source: str
    target: str
    type: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "metadata": self.metadata,
        }


@dataclass
class IdentityGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    clusters: list[list[str]] = field(default_factory=list)

    def _ensure_node(
        self,
        node_type: str,
        value: str,
        label: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        value = value.strip()
        if not value:
            return ""
        nid = _node_id(node_type, value.lower())
        if nid not in self.nodes:
            self.nodes[nid] = GraphNode(
                id=nid,
                type=node_type,
                label=label or value[:40],
                value=value,
                metadata=metadata or {},
            )
        elif metadata:
            self.nodes[nid].metadata.update(metadata)
        return nid

    def _add_edge(self, source: str, target: str, edge_type: str, **meta: Any) -> None:
        if not source or not target or source == target:
            return
        for edge in self.edges:
            if edge.source == source and edge.target == target and edge.type == edge_type:
                return
        self.edges.append(GraphEdge(source=source, target=target, type=edge_type, metadata=meta))

    def _link_shared(
        self,
        attr_type: str,
        value: str,
        platform_nid: str,
        edge_type: str,
    ) -> None:
        attr_nid = self._ensure_node(attr_type, value)
        if not attr_nid or not platform_nid:
            return
        self._add_edge(platform_nid, attr_nid, edge_type)

    @classmethod
    def build(cls, investigation_result: dict[str, Any]) -> IdentityGraph:
        """
        Build an identity graph from investigation findings.

        investigation_result expects:
          - email: str
          - findings: list of {module_name, data} or flat finding dicts
        """
        graph = cls()
        email = investigation_result.get("email", "")
        if email:
            graph._ensure_node("email", email, label=email)

        raw_findings = investigation_result.get("findings", [])
        flat: list[tuple[str, dict[str, Any]]] = []
        for item in raw_findings:
            if isinstance(item, dict) and "data" in item:
                flat.append((item.get("module_name", ""), item["data"]))
            elif isinstance(item, dict):
                flat.append((item.get("module_name", ""), item))

        # attr_value -> list of platform node ids (for shared-attribute edges)
        attr_index: dict[tuple[str, str], list[str]] = {}
        platform_nodes: list[str] = []

        for module_name, finding in flat:
            if not isinstance(finding, dict):
                continue
            platform = str(finding.get("platform") or module_name or "unknown")
            platform_nid = graph._ensure_node(
                "platform",
                platform,
                label=platform,
                metadata={"module": module_name},
            )
            platform_nodes.append(platform_nid)

            if email:
                graph._add_edge(graph._ensure_node("email", email), platform_nid, "same_platform_group")

            payloads = [finding]
            meta = finding.get("metadata")
            if isinstance(meta, dict):
                payloads.append(meta)

            username: str | None = None
            display_name: str | None = None
            photo_url: str | None = None
            domain: str | None = None

            for payload in payloads:
                if not isinstance(payload, dict):
                    continue
                for key in _USERNAME_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip():
                        username = val.strip()
                for key in _DISPLAY_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip():
                        display_name = val.strip()
                for key in _PHOTO_KEYS:
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip().startswith("http"):
                        photo_url = val.strip()
                for key in ("domain", "breach_domain"):
                    val = payload.get(key)
                    if isinstance(val, str) and val.strip():
                        domain = val.strip()

            profile_url = finding.get("profile_url") or finding.get("url")
            if isinstance(profile_url, str) and profile_url.startswith("http"):
                parsed = urlparse(profile_url)
                if parsed.netloc and not domain:
                    domain = parsed.netloc.lstrip("www.")

            if username:
                graph._link_shared("username", username, platform_nid, "shared_username")
                attr_index.setdefault(("username", username.lower()), []).append(platform_nid)
            if display_name:
                graph._link_shared("display_name", display_name, platform_nid, "shared_display_name")
                attr_index.setdefault(("display_name", display_name.lower()), []).append(
                    platform_nid
                )
            if photo_url:
                graph._link_shared("photo_url", photo_url, platform_nid, "shared_photo")
                attr_index.setdefault(("photo_url", photo_url), []).append(platform_nid)
            if domain:
                dom_nid = graph._ensure_node("domain", domain)
                graph._add_edge(platform_nid, dom_nid, "same_platform_group")

            phone = None
            for key in ("phone_number", "phone_hint", "phone"):
                val = (meta or {}).get(key) if isinstance(meta, dict) else None
                if isinstance(val, str) and val:
                    phone = val
            if phone:
                phone_nid = graph._ensure_node("phone", phone, metadata={"masked": True})
                graph._add_edge(platform_nid, phone_nid, "same_platform_group")

            if module_name in _BREACH_MODULES or finding.get("severity") in ("critical", "high"):
                if email:
                    graph._add_edge(
                        graph._ensure_node("email", email),
                        platform_nid,
                        "breach_confirmed",
                        module=module_name,
                    )

        # Cross-platform edges for shared attributes
        for (attr_type, attr_val), platform_nids in attr_index.items():
            unique = list(dict.fromkeys(platform_nids))
            if len(unique) < 2:
                continue
            edge_map = {
                "username": "shared_username",
                "display_name": "shared_display_name",
                "photo_url": "shared_photo",
            }
            edge_type = edge_map.get(attr_type, "same_platform_group")
            for i, a in enumerate(unique):
                for b in unique[i + 1 :]:
                    graph._add_edge(a, b, edge_type, shared_attribute=attr_val)

        graph._score_nodes()
        graph._identify_clusters()
        return graph

    def _score_nodes(self) -> None:
        degree: dict[str, int] = {nid: 0 for nid in self.nodes}
        for edge in self.edges:
            if edge.source in degree:
                degree[edge.source] += 1
            if edge.target in degree:
                degree[edge.target] += 1
        for nid, deg in degree.items():
            self.nodes[nid].degree = deg
            self.nodes[nid].high_confidence_node = deg >= 3

    def _identify_clusters(self) -> None:
        """Union-find platform nodes connected via shared-attribute edges."""
        parent: dict[str, str] = {nid: nid for nid in self.nodes}

        def find(x: str) -> str:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: str, b: str) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[rb] = ra

        shared_types = frozenset({
            "shared_username",
            "shared_photo",
            "shared_display_name",
        })
        for edge in self.edges:
            if edge.type in shared_types:
                if edge.source in parent and edge.target in parent:
                    union(edge.source, edge.target)

        groups: dict[str, list[str]] = {}
        for nid, node in self.nodes.items():
            if node.type != "platform":
                continue
            root = find(nid)
            groups.setdefault(root, []).append(nid)

        self.clusters = [g for g in groups.values() if len(g) >= 2]

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
            "clusters": self.clusters,
        }

    def to_d3(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "nodes": [
                {
                    "id": n.id,
                    "type": n.type,
                    "label": n.label,
                    "value": n.value,
                    "degree": n.degree,
                    "high_confidence_node": n.high_confidence_node,
                    "metadata": n.metadata,
                }
                for n in self.nodes.values()
            ],
            "links": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.type,
                    "metadata": e.metadata,
                }
                for e in self.edges
            ],
        }

    def to_neo4j_cypher(self) -> str:
        lines: list[str] = ["// MailAccess identity graph export"]
        for node in self.nodes.values():
            safe_label = re.sub(r"[^a-zA-Z0-9_]", "_", node.type)
            props = {
                "id": node.id,
                "label": node.label,
                "value": node.value,
                "degree": node.degree,
                "high_confidence_node": node.high_confidence_node,
            }
            props_str = ", ".join(f"{k}: {repr(v)}" for k, v in props.items())
            lines.append(f"CREATE (:{safe_label} {{{props_str}}})")
        for edge in self.edges:
            lines.append(
                f"MATCH (a {{id: {edge.source!r}}}), (b {{id: {edge.target!r}}}) "
                f"CREATE (a)-[:{edge.type.upper()}]->(b)"
            )
        return "\n".join(lines)
