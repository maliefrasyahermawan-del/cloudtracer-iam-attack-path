"""Parse AWS IAM get-account-authorization-details JSON dump into structured entities."""

import json
import urllib.parse
from typing import Any


def _decode_policy_doc(doc: Any) -> dict:
    """URL-decode and parse a policy document (may be URL-encoded string or dict)."""
    if isinstance(doc, str):
        doc = urllib.parse.unquote(doc)
        doc = json.loads(doc)
    return doc


def _extract_statements(policy_doc: dict) -> list[dict]:
    """Flatten policy document into a list of statements."""
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        stmts = [stmts]
    return stmts


def _collect_actions(statements: list[dict]) -> list[str]:
    """Collect all Allow actions from statements."""
    actions = []
    for stmt in statements:
        if stmt.get("Effect", "Allow") != "Allow":
            continue
        action = stmt.get("Action", [])
        if isinstance(action, str):
            action = [action]
        actions.extend(action)
    return actions


def parse_iam_dump(data: dict) -> dict:
    """
    Parse IAM account-authorization-details JSON into a structured dict.

    Returns:
        {
            "users": [...],
            "groups": [...],
            "roles": [...],
            "policies": {...}   # keyed by PolicyArn
        }
    """
    result = {"users": [], "groups": [], "roles": [], "policies": {}}

    # ── Policies ────────────────────────────────────────────────────────────
    for pol in data.get("Policies", []):
        arn = pol.get("Arn", "")
        name = pol.get("PolicyName", "")
        actions = []
        for ver in pol.get("PolicyVersionList", []):
            if ver.get("IsDefaultVersion"):
                doc = _decode_policy_doc(ver.get("Document", {}))
                actions = _collect_actions(_extract_statements(doc))
                break
        result["policies"][arn] = {"name": name, "arn": arn, "actions": actions}

    # ── Users ────────────────────────────────────────────────────────────────
    for u in data.get("UserDetailList", []):
        inline_actions = []
        for ip in u.get("UserPolicyList", []):
            doc = _decode_policy_doc(ip.get("PolicyDocument", {}))
            inline_actions.extend(_collect_actions(_extract_statements(doc)))

        result["users"].append(
            {
                "id": u.get("UserId", ""),
                "name": u.get("UserName", ""),
                "arn": u.get("Arn", ""),
                "groups": u.get("GroupList", []),
                "attached_policies": [
                    p.get("PolicyArn", "") for p in u.get("AttachedManagedPolicies", [])
                ],
                "inline_actions": inline_actions,
            }
        )

    # ── Groups ───────────────────────────────────────────────────────────────
    for g in data.get("GroupDetailList", []):
        inline_actions = []
        for ip in g.get("GroupPolicyList", []):
            doc = _decode_policy_doc(ip.get("PolicyDocument", {}))
            inline_actions.extend(_collect_actions(_extract_statements(doc)))

        result["groups"].append(
            {
                "id": g.get("GroupId", ""),
                "name": g.get("GroupName", ""),
                "arn": g.get("Arn", ""),
                "attached_policies": [
                    p.get("PolicyArn", "") for p in g.get("AttachedManagedPolicies", [])
                ],
                "inline_actions": inline_actions,
            }
        )

    # ── Roles ────────────────────────────────────────────────────────────────
    for r in data.get("RoleDetailList", []):
        inline_actions = []
        for ip in r.get("RolePolicyList", []):
            doc = _decode_policy_doc(ip.get("PolicyDocument", {}))
            inline_actions.extend(_collect_actions(_extract_statements(doc)))

        # Parse trust policy principals
        trust_principals = []
        trust_doc = _decode_policy_doc(r.get("AssumeRolePolicyDocument", {}))
        for stmt in _extract_statements(trust_doc):
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if isinstance(principal, str):
                trust_principals.append(principal)
            elif isinstance(principal, dict):
                for v in principal.values():
                    if isinstance(v, list):
                        trust_principals.extend(v)
                    else:
                        trust_principals.append(v)

        result["roles"].append(
            {
                "id": r.get("RoleId", ""),
                "name": r.get("RoleName", ""),
                "arn": r.get("Arn", ""),
                "attached_policies": [
                    p.get("PolicyArn", "") for p in r.get("AttachedManagedPolicies", [])
                ],
                "inline_actions": inline_actions,
                "trust_principals": trust_principals,
            }
        )

    return result
