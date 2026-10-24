"""Compute risk scores for IAM entities based on graph position and permissions."""

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

RISK_LABELS = [
    (80, "CRITICAL"),
    (60, "HIGH"),
    (40, "MEDIUM"),
    (0,  "LOW"),
]


def _label(score: int) -> str:
    for threshold, label in RISK_LABELS:
        if score >= threshold:
            return label
    return "LOW"


def _shortest_hop(G: nx.DiGraph, src: str, targets: list[str]) -> int | None:
    """Return the minimum hop count from src to any target, or None."""
    best = None
    for tgt in targets:
        if not G.has_node(tgt):
            continue
        try:
            length = nx.shortest_path_length(G, source=src, target=tgt)
            if best is None or length < best:
                best = length
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass
    return best


def _all_actions_for_node(G: nx.DiGraph, node: str) -> list[str]:
    """Collect all actions reachable from a node via attached/inline policies."""
    actions = []
    for neighbor in G.successors(node):
        nd = G.nodes[neighbor]
        if nd.get("node_type") == "policy":
            actions.extend(nd.get("actions", []))
            for perm_node in G.successors(neighbor):
                if G.nodes[perm_node].get("node_type") == "permission":
                    actions.append(G.nodes[perm_node].get("name", ""))
    return [a.lower() for a in actions]


def score_entity(node: str, G: nx.DiGraph, targets: list[str]) -> dict:
    """
    Compute risk score (0-100) and label for a single IAM entity node.

    Returns:
        {"node": str, "score": int, "label": str, "reasons": [...]}
    """
    nd = G.nodes.get(node, {})
    reasons = []
    base = 0

    # ── Distance to dangerous targets ───────────────────────────────────────
    hop = _shortest_hop(G, node, targets)
    if hop is not None:
        if hop <= 1:
            base += 40; reasons.append(f"1 hop to dangerous target (+40)")
        elif hop == 2:
            base += 25; reasons.append(f"2 hops to dangerous target (+25)")
        elif hop == 3:
            base += 15; reasons.append(f"3 hops to dangerous target (+15)")
        else:
            base += 8;  reasons.append(f"{hop} hops to dangerous target (+8)")

    # ── Permission-based scoring ─────────────────────────────────────────────
    actions = _all_actions_for_node(G, node)
    action_set = set(actions)

    if "*" in action_set:
        base += 35; reasons.append("Wildcard action '*' (+35)")
    if "iam:*" in action_set:
        base += 30; reasons.append("IAM wildcard 'iam:*' (+30)")
    if "iam:passrole" in action_set and "*" not in action_set:
        base += 20; reasons.append("iam:PassRole on * (+20)")
    if "iam:attachuserpolicy" in action_set:
        base += 18; reasons.append("iam:AttachUserPolicy (+18)")
    if "sts:assumerole" in action_set:
        base += 22; reasons.append("sts:AssumeRole capability (+22)")

    # ── Trust policy issues (roles only) ────────────────────────────────────
    if nd.get("node_type") == "role":
        trust_principals = nd.get("trust_principals", [])
        if "*" in trust_principals:
            base += 25; reasons.append("Trust principal is '*' (open) (+25)")
        elif any("AWS:*" in p for p in trust_principals):
            base += 20; reasons.append("Trust principal AWS:* (+20)")
        # Cross-account: principal contains a different account ID
        own_account = None
        arn = nd.get("arn", "")
        if "arn:aws:iam::" in arn:
            own_account = arn.split(":")[4]
        if own_account:
            for p in trust_principals:
                if "arn:aws:iam::" in p and own_account not in p:
                    base += 10; reasons.append("Cross-account trust (+10)"); break

    final = min(base, 100)
    return {"node": node, "score": final, "label": _label(final), "reasons": reasons}


def score_all(G: nx.DiGraph, findings: list[dict]) -> dict[str, dict]:
    """
    Score every user and role node in the graph.

    Returns mapping: node_id → {score, label, reasons}
    """
    targets = [t for t in DANGEROUS_TARGETS if G.has_node(t)]
    scored = {}
    for node, data in G.nodes(data=True):
        if data.get("node_type") in ("user", "role"):
            scored[node] = score_entity(node, G, targets)
    # Attach scores to graph node attributes for downstream use
    for node, result in scored.items():
        G.nodes[node]["risk_score"] = result["score"]
        G.nodes[node]["risk_label"] = result["label"]
        G.nodes[node]["risk_reasons"] = result["reasons"]
    return scored
