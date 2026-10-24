# CloudTracer — AWS IAM Attack-Path Visualizer

> A local analysis tool that maps AWS IAM relationships, identifies privilege-escalation paths, scores risk, and renders the result as an interactive graph.

## What this project does

CloudTracer accepts an AWS IAM authorization-details JSON export, turns identities, groups, roles, policies, trust relationships, and risky permissions into a directed graph, then searches for routes that could lead to elevated privilege. It provides both a browser-based interface and a command-line workflow.

## Core functions

- Parse IAM users, groups, roles, policies, attachments, and trust policies from an account authorization export.
- Identify dangerous permissions and targets such as wildcard access, `iam:PassRole`, `sts:AssumeRole`, and administrator-level access.
- Find possible privilege-escalation paths with graph traversal.
- Assign CRITICAL, HIGH, MEDIUM, or LOW risk scores.
- Generate interactive Pyvis/vis.js graphs and JSON findings.
- Serve upload, graph, findings, summary, and health endpoints through FastAPI.

## Architecture

```text
IAM authorization-details JSON
  │
  ▼
IAM parser → normalized users / roles / groups / policies
  │
  ▼
NetworkX graph builder → attack-path finder → risk scorer
  │
  ├── Interactive HTML graph
  ├── findings.json
  └── risk summary
```

## Technology

- Python and FastAPI
- NetworkX for IAM relationship graphs and path analysis
- Pyvis/vis.js for visualisation
- Uvicorn for local serving

## Run locally

```bash
cd cloudtracer
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt

python run.py
# Open http://localhost:8000

# Or use the command line
python cli.py --input sample_data/sample_iam_dump.json --output output/
```

## Repository layout

```text
cloudtracer/
├── app/           # Parser, graph builder, path finder, scorer, visualizer
├── static/        # Browser interface
├── sample_data/   # Safe example IAM authorization dump
├── output/        # Generated reports (ignored by Git)
├── cli.py         # Command-line entry point
└── run.py         # Local FastAPI entry point
```

## Safety and privacy

Use exports only from AWS accounts you own or are authorized to assess. IAM exports can reveal account structure and privilege relationships, so generated reports are ignored from version control by default. CloudTracer is an analysis aid; validate every reported path against actual IAM conditions before remediation.
