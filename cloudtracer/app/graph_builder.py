"""Build a directed NetworkX graph from parsed IAM entities."""

import networkx as nx

DANGEROUS_ACTIONS = {
    "iam:createuser",
    "iam:attachuserpolicy",
    "iam:putuseropolicy",
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "sts:assumerole",
    "iam:*",
    "*",
}


def _is_dangerous(action: str) -> bool:
    """Return True if the action string is considered dangerous."""
    a = action.lower()
    return a in DANGEROUS_ACTIONS or a == "iam:*" or a == "*"


def _short_label(name: str, max_len: int = 22) -> str:
    """Truncate long names with ellipsis."""
    return name if len(name) <= max_len else name[:max_len - 1] + "…"


def build_graph(parsed: dict) -> nx.DiGraph:
    """
    Construct a directed graph representing IAM relationships.

    Node IDs follow the convention:
      user:{name}, group:{name}, role:{name},
      policy:{name}, permission:{action}
    """
    G = nx.DiGraph()

    policies = parsed["policies"]  # arn → {name, arn, actions}

    # Helper to get/create a policy node
    def ensure_policy_node(arn: str):
        pol = policies.get(arn)
        if pol is None:
            name = arn.split("/")[-1]
            pol = {"name": name, "arn": arn, "actions": []}
        nid = f"policy:{pol['name']}"
        if not G.has_node(nid):
            G.add_node(
                nid,
                node_type="policy",
                label=_short_label(pol["name"]),
                name=pol["name"],
                arn=arn,
                actions=pol["actions"],
            )
        return nid, pol["actions"]

    def add_permission_edges(from_node: str, actions: list[str]):
        for action in actions:
            if _is_dangerous(action):
                perm_id = f"permission:{action.lower()}"
                if not G.has_node(perm_id):
                    G.add_node(
                        perm_id,
                        node_type="permission",
                        label=_short_label(action),
                        name=action,
                    )
                G.add_edge(from_node, perm_id, edge_type="Allows")

    # ── Users ────────────────────────────────────────────────────────────────
    for u in parsed["users"]:
        uid = f"user:{u['name']}"
        G.add_node(uid, node_type="user", label=_short_label(u["name"]), name=u["name"], arn=u["arn"])

        for grp_name in u["groups"]:
            gid = f"group:{grp_name}"
            if not G.has_node(gid):
                G.add_node(gid, node_type="group", label=_short_label(grp_name), name=grp_name)
            G.add_edge(uid, gid, edge_type="MemberOf")

        for pol_arn in u["attached_policies"]:
            pnid, actions = ensure_policy_node(pol_arn)
            G.add_edge(uid, pnid, edge_type="DirectlyAttached")
            add_permission_edges(pnid, actions)

        if u["inline_actions"]:
            inline_id = f"policy:inline-user-{u['name']}"
            G.add_node(inline_id, node_type="policy", label=f"inline({u['name']})", name=f"inline-{u['name']}", actions=u["inline_actions"])
            G.add_edge(uid, inline_id, edge_type="DirectlyAttached")
            add_permission_edges(inline_id, u["inline_actions"])

    # ── Groups ───────────────────────────────────────────────────────────────
    for g in parsed["groups"]:
        gid = f"group:{g['name']}"
        if not G.has_node(gid):
            G.add_node(gid, node_type="group", label=_short_label(g["name"]), name=g["name"], arn=g["arn"])
        else:
            G.nodes[gid]["arn"] = g["arn"]

        for pol_arn in g["attached_policies"]:
            pnid, actions = ensure_policy_node(pol_arn)
            G.add_edge(gid, pnid, edge_type="GroupAttached")
            add_permission_edges(pnid, actions)

        if g["inline_actions"]:
            inline_id = f"policy:inline-group-{g['name']}"
            G.add_node(inline_id, node_type="policy", label=f"inline({g['name']})", name=f"inline-{g['name']}", actions=g["inline_actions"])
            G.add_edge(gid, inline_id, edge_type="GroupAttached")
            add_permission_edges(inline_id, g["inline_actions"])

    # ── Roles ────────────────────────────────────────────────────────────────
    for r in parsed["roles"]:
        rid = f"role:{r['name']}"
        G.add_node(rid, node_type="role", label=_short_label(r["name"]), name=r["name"], arn=r["arn"], trust_principals=r["trust_principals"])

        for pol_arn in r["attached_policies"]:
            pnid, actions = ensure_policy_node(pol_arn)
            G.add_edge(rid, pnid, edge_type="RoleAttached")
            add_permission_edges(pnid, actions)

        if r["inline_actions"]:
            inline_id = f"policy:inline-role-{r['name']}"
            G.add_node(inline_id, node_type="policy", label=f"inline({r['name']})", name=f"inline-{r['name']}", actions=r["inline_actions"])
            G.add_edge(rid, inline_id, edge_type="RoleAttached")
            add_permission_edges(inline_id, r["inline_actions"])

        # Trust policy: who can assume this role
        for principal in r["trust_principals"]:
            # Match principal ARN to existing user/role nodes
            for u in parsed["users"]:
                if u["arn"] == principal or principal in ("*", "AWS:*"):
                    G.add_edge(f"user:{u['name']}", rid, edge_type="CanAssume")
            for other_r in parsed["roles"]:
                if other_r["arn"] == principal or principal in ("*", "AWS:*"):
                    G.add_edge(f"role:{other_r['name']}", rid, edge_type="CanAssume")

    return G
