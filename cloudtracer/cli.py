"""CLI entry point for CloudTracer — no web server required."""

import argparse
import json
import os
import sys
from pathlib import Path

# Ensure project root is on path when run directly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.graph_builder import build_graph
from app.iam_parser import parse_iam_dump
from app.path_finder import find_attack_paths
from app.risk_scorer import score_all
from app.visualizer import generate_graph_html


def _print_table(findings: list[dict]):
    """Print ASCII risk findings table."""
    header = f"{'SOURCE':<30} {'TARGET':<35} {'HOPS':>4} {'SCORE':>5} {'LABEL':<10}"
    sep = "-" * len(header)
    print(sep)
    print(header)
    print(sep)
    for f in findings[:20]:
        src = f["source"][:29]
        tgt = f["target"][:34]
        print(f"{src:<30} {tgt:<35} {f['hop_count']:>4} {f['risk_score']:>5} {f['risk_label']:<10}")
    if len(findings) > 20:
        print(f"  ... and {len(findings) - 20} more findings")
    print(sep)


def main():
    parser = argparse.ArgumentParser(
        description="CloudTracer — AWS IAM attack path visualizer (CLI mode)"
    )
    parser.add_argument("--input", "-i", required=True, help="Path to IAM JSON dump")
    parser.add_argument("--output", "-o", default="output/", help="Output directory")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[ERROR] Input file not found: {input_path}", file=sys.stderr)
        sys.exit(1)

    try:
        raw = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)

    print("[*] Parsing IAM data...")
    parsed = parse_iam_dump(raw)
    print(f"    Users: {len(parsed['users'])}  Groups: {len(parsed['groups'])}  "
          f"Roles: {len(parsed['roles'])}  Policies: {len(parsed['policies'])}")

    print("[*] Building graph...")
    G = build_graph(parsed)
    print(f"    Nodes: {G.number_of_nodes()}  Edges: {G.number_of_edges()}")

    print("[*] Finding attack paths (cutoff=5)...")
    paths = find_attack_paths(G)
    print(f"    Paths found: {len(paths)}")

    print("[*] Scoring entities...")
    scores = score_all(G, paths)

    # Build sorted findings list
    findings = []
    for f in paths:
        src_score = scores.get(f["source"], {})
        findings.append(
            {
                "source": f["source"],
                "target": f["target"],
                "shortest_path": f["shortest_path"],
                "hop_count": f["hop_count"],
                "path_count": len(f["paths"]),
                "risk_score": src_score.get("score", 0),
                "risk_label": src_score.get("label", "LOW"),
                "reasons": src_score.get("reasons", []),
            }
        )
    findings.sort(key=lambda x: x["risk_score"], reverse=True)

    # Risk summary counts
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in scores.values():
        counts[s["label"]] = counts.get(s["label"], 0) + 1

    print("\n" + "=" * 70)
    print("  CLOUDTRACER RISK SUMMARY")
    print("=" * 70)
    total_entities = len(parsed["users"]) + len(parsed["roles"])
    print(f"  Total IAM entities : {total_entities}")
    print(f"  CRITICAL           : {counts['CRITICAL']}")
    print(f"  HIGH               : {counts['HIGH']}")
    print(f"  MEDIUM             : {counts['MEDIUM']}")
    print(f"  LOW                : {counts['LOW']}")
    print(f"  Attack paths found : {len(findings)}")
    print("=" * 70 + "\n")

    if findings:
        print("TOP ATTACK PATHS:")
        _print_table(findings)

    # Save outputs
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    findings_path = out_dir / "findings.json"
    findings_path.write_text(json.dumps(findings, indent=2), encoding="utf-8")
    print(f"\n[+] Findings saved to: {findings_path}")

    graph_path = out_dir / "graph.html"
    generate_graph_html(G, str(graph_path))
    print(f"[+] Graph saved to:    {graph_path}")
    print(f"\n    Open in browser: file:///{graph_path.resolve().as_posix()}")

    summary_path = out_dir / "risk_summary.txt"
    summary_path.write_text(
        f"CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | "
        f"MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']} | "
        f"Paths: {len(findings)}\n",
        encoding="utf-8",
    )
    print(f"[+] Summary saved to: {summary_path}")


if __name__ == "__main__":
    main()
