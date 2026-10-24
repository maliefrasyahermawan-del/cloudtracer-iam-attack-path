"""Generate interactive Pyvis HTML graph from the scored IAM NetworkX graph."""

import os
from pyvis.network import Network
import networkx as nx

# Color palette
NODE_COLORS = {
    "user":       {"CRITICAL": "#e74c3c", "HIGH": "#e67e22", "MEDIUM": "#f1c40f", "LOW": "#3498db", "DEFAULT": "#3498db"},
    "role":       {"CRITICAL": "#c0392b", "HIGH": "#d35400", "MEDIUM": "#f39c12", "LOW": "#27ae60", "DEFAULT": "#27ae60"},
    "group":      "#e67e22",
    "policy":     "#95a5a6",
    "permission": "#e74c3c",
}

EDGE_COLORS = {
    "MemberOf":        "#3498db",
    "DirectlyAttached":"#95a5a6",
    "GroupAttached":   "#e67e22",
    "RoleAttached":    "#27ae60",
    "Allows":          "#e74c3c",
    "CanAssume":       "#9b59b6",
}


def _node_color(data: dict) -> str:
    ntype = data.get("node_type", "policy")
    if ntype in ("user", "role"):
        palette = NODE_COLORS[ntype]
        label = data.get("risk_label", "LOW")
        return palette.get(label, palette["DEFAULT"])
    return NODE_COLORS.get(ntype, "#cccccc")


def _node_size(data: dict) -> int:
    score = data.get("risk_score", 10)
    return 15 + int(score / 5)


def _tooltip(node_id: str, data: dict) -> str:
    lines = [f"<b>{node_id}</b>", f"Type: {data.get('node_type', '?')}"]
    if "risk_score" in data:
        lines.append(f"Risk: {data['risk_label']} ({data['risk_score']}/100)")
        for r in data.get("risk_reasons", []):
            lines.append(f"  • {r}")
    if data.get("actions"):
        lines.append("Permissions:")
        for a in data["actions"][:10]:
            lines.append(f"  • {a}")
        if len(data["actions"]) > 10:
            lines.append(f"  … +{len(data['actions']) - 10} more")
    if data.get("trust_principals"):
        lines.append("Trust principals:")
        for p in data["trust_principals"][:5]:
            lines.append(f"  • {p}")
    return "<br>".join(lines)


def generate_graph_html(G: nx.DiGraph, output_path: str) -> str:
    """
    Render the NetworkX graph to an interactive Pyvis HTML file.

    Returns the path to the generated HTML file.
    """
    net = Network(
        height="750px",
        width="100%",
        bgcolor="#1a1a2e",
        font_color="white",
        directed=True,
    )
    net.barnes_hut(gravity=-8000, central_gravity=0.3, spring_length=150)

    for node_id, data in G.nodes(data=True):
        net.add_node(
            node_id,
            label=data.get("label", node_id),
            title=_tooltip(node_id, data),
            color=_node_color(data),
            size=_node_size(data),
        )

    for src, dst, edata in G.edges(data=True):
        etype = edata.get("edge_type", "")
        net.add_edge(
            src,
            dst,
            color=EDGE_COLORS.get(etype, "#aaaaaa"),
            title=etype,
            arrows="to",
        )

    net.set_options("""
{
  "physics": {
    "enabled": true,
    "barnesHut": {
      "gravitationalConstant": -8000,
      "centralGravity": 0.3,
      "springLength": 150,
      "springConstant": 0.04,
      "damping": 0.09
    },
    "stabilization": {"iterations": 150}
  },
  "interaction": {
    "hover": true,
    "tooltipDelay": 100
  },
  "edges": {
    "smooth": {"type": "curvedCW", "roundness": 0.2}
  }
}
""")

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    net.save_graph(output_path)
    return output_path
