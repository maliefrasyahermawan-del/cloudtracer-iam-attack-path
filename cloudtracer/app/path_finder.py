"""Find attack paths in the IAM graph using NetworkX path algorithms."""

import networkx as nx

DANGEROUS_TARGETS = [
    "policy:AdministratorAccess",
    "permission:iam:createuser",
    "permission:iam:attachuserpolicy",
    "permission:iam:putuseropolicy",
    "permission:iam:passrole",
    "permission:sts:assumerole",
    "permission:iam:createpolicyversion",
    "permission:iam:setdefaultpolicyversion",
    "permission:iam:*",
    "permission:*",
]

SOURCE_TYPES = {"user", "role"}


def find_attack_paths(G: nx.DiGraph, cutoff: int = 5) -> list[dict]:
    """
    Find all attack paths from non-admin users/roles to dangerous targets.

    Returns a list of finding dicts:
      {
        "source": node_id,
        "target": node_id,
        "paths": [[node, ...], ...],
        "shortest_path": [node, ...],
        "hop_count": int
      }
    """
    findings = []

    # Only nodes that actually exist in the graph
    targets = [t for t in DANGEROUS_TARGETS if G.has_node(t)]

    sources = [
        n for n, d in G.nodes(data=True)
        if d.get("node_type") in SOURCE_TYPES
    ]

    for src in sources:
        for tgt in targets:
            if src == tgt:
                continue
            try:
                all_paths = list(
                    nx.all_simple_paths(G, source=src, target=tgt, cutoff=cutoff)
                )
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                all_paths = []

            if not all_paths:
                continue

            shortest = min(all_paths, key=len)
            findings.append(
                {
                    "source": src,
                    "target": tgt,
                    "paths": all_paths,
                    "shortest_path": shortest,
                    "hop_count": len(shortest) - 1,
                }
            )

    return findings
