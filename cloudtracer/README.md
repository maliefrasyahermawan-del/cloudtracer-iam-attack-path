# CloudTracer

AWS IAM Attack Path Visualizer — finds privilege escalation paths in IAM environments and renders them as an interactive graph.

## What it does

1. Accepts an IAM JSON dump (`aws iam get-account-authorization-details`)
2. Builds a directed graph of users, roles, groups, policies, and dangerous permissions
3. Finds all paths from any entity to dangerous targets (AdministratorAccess, iam:PassRole, etc.)
4. Scores each entity with a risk score (0-100) and label (CRITICAL / HIGH / MEDIUM / LOW)
5. Outputs an interactive HTML graph (Pyvis/vis.js) + `findings.json`

## Quick start

```bash
# Install dependencies
pip install -r requirements.txt

# Web UI mode
python run.py
# Open http://localhost:8000 and upload sample_data/sample_iam_dump.json

# CLI mode (no server)
python cli.py --input sample_data/sample_iam_dump.json --output output/
# Then open output/graph.html in your browser
```

## Folder structure

```
cloudtracer/
├── app/
│   ├── main.py          FastAPI endpoints
│   ├── iam_parser.py    JSON → structured entities
│   ├── graph_builder.py NetworkX graph construction
│   ├── path_finder.py   BFS attack path detection
│   ├── risk_scorer.py   Risk scoring logic
│   └── visualizer.py    Pyvis HTML generator
├── cli.py               CLI entry point
├── static/index.html    Web UI (upload + dashboard)
├── sample_data/         Sample IAM dump with vuln configs
├── output/              Generated graph.html + findings.json
├── requirements.txt
└── run.py               Uvicorn entry point
```

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/upload` | Upload IAM JSON, returns `job_id` |
| GET | `/graph/{job_id}` | Interactive Pyvis graph HTML |
| GET | `/findings/{job_id}` | Attack findings as JSON |
| GET | `/summary/{job_id}` | Plain-text risk summary |
| GET | `/health` | Health check |

## Risk scoring

| Score | Label | Conditions |
|-------|-------|-----------|
| 80-100 | CRITICAL | Direct wildcard `*`, 1-hop to admin |
| 60-79 | HIGH | `iam:PassRole`, `sts:AssumeRole`, 2-hop paths |
| 40-59 | MEDIUM | Indirect paths, cross-account trust |
| 0-39 | LOW | Minimal privilege escalation surface |

## Sample scenario

The included `sample_iam_dump.json` demonstrates:

- **alice** (low-privilege) → group `developers` → `DevPolicy` → `iam:PassRole` → `admin-role` → **AdministratorAccess**
- **bob** (developer) has `DevPolicy` directly attached — same escalation path, fewer hops
- **lambda-exec-role** has an open trust policy (`"Principal": "*"`) — HIGH risk
- **charlie** (billing) has read-only access — LOW risk
