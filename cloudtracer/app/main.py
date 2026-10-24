"""FastAPI web server for CloudTracer — upload IAM JSON, get attack graph."""

import json
import os
import sqlite3
import uuid
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.graph_builder import build_graph
from app.iam_parser import parse_iam_dump
from app.path_finder import find_attack_paths
from app.risk_scorer import score_all
from app.visualizer import generate_graph_html

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"
STATIC_DIR = BASE_DIR / "static"
DB_PATH = OUTPUT_DIR / "cache.db"

OUTPUT_DIR.mkdir(exist_ok=True)

app = FastAPI(title="CloudTracer", version="1.0.0")

# ── SQLite cache ─────────────────────────────────────────────────────────────

def _get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute(
        """CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            findings TEXT,
            summary TEXT
        )"""
    )
    conn.commit()
    return conn


# ── Processing pipeline ───────────────────────────────────────────────────────

def _process_iam(raw: dict) -> tuple[str, dict, str]:
    """Parse → build graph → find paths → score → visualize. Returns (job_id, findings, summary)."""
    job_id = str(uuid.uuid4())[:8]
    job_dir = OUTPUT_DIR / job_id
    job_dir.mkdir(exist_ok=True)

    parsed = parse_iam_dump(raw)
    G = build_graph(parsed)
    paths = find_attack_paths(G)
    scores = score_all(G, paths)

    # Build findings list
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

    # Risk summary
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for s in scores.values():
        counts[s["label"]] = counts.get(s["label"], 0) + 1

    total_entities = len(parsed["users"]) + len(parsed["roles"])
    summary = (
        f"Total IAM entities: {total_entities} | "
        f"CRITICAL: {counts['CRITICAL']} | HIGH: {counts['HIGH']} | "
        f"MEDIUM: {counts['MEDIUM']} | LOW: {counts['LOW']} | "
        f"Attack paths found: {len(findings)}"
    )

    # Persist files
    findings_path = job_dir / "findings.json"
    findings_path.write_text(json.dumps(findings, indent=2))

    graph_path = job_dir / "graph.html"
    generate_graph_html(G, str(graph_path))

    # Cache in SQLite
    db = _get_db()
    db.execute(
        "INSERT OR REPLACE INTO jobs VALUES (?, ?, ?)",
        (job_id, json.dumps(findings), summary),
    )
    db.commit()
    db.close()

    return job_id, findings, summary


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
def index():
    html_path = STATIC_DIR / "index.html"
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="index.html not found")
    return HTMLResponse(html_path.read_text(encoding="utf-8"))


@app.post("/upload")
async def upload(file: UploadFile = File(...)):
    """Accept IAM JSON dump, process it, return job_id and summary."""
    if not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only .json files are accepted")

    content = await file.read()
    try:
        raw = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file")

    required_keys = {"UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"}
    if not required_keys.intersection(raw.keys()):
        raise HTTPException(
            status_code=422,
            detail="JSON does not appear to be an IAM account-authorization-details dump",
        )

    try:
        job_id, findings, summary = _process_iam(raw)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Processing error: {e}")

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        lbl = f.get("risk_label", "LOW")
        counts[lbl] = counts.get(lbl, 0) + 1

    return JSONResponse(
        {
            "job_id": job_id,
            "summary": summary,
            "finding_counts": counts,
            "total_paths": len(findings),
        }
    )


@app.get("/graph/{job_id}", response_class=HTMLResponse)
def get_graph(job_id: str):
    """Serve the interactive Pyvis graph HTML for a job."""
    graph_path = OUTPUT_DIR / job_id / "graph.html"
    if not graph_path.exists():
        raise HTTPException(status_code=404, detail="Graph not found")
    return HTMLResponse(graph_path.read_text(encoding="utf-8"))


@app.get("/findings/{job_id}")
def get_findings(job_id: str):
    """Return findings JSON for a job."""
    findings_path = OUTPUT_DIR / job_id / "findings.json"
    if not findings_path.exists():
        raise HTTPException(status_code=404, detail="Findings not found")
    return JSONResponse(json.loads(findings_path.read_text()))


@app.get("/summary/{job_id}")
def get_summary(job_id: str):
    """Return plain-text risk summary for a job."""
    db = _get_db()
    row = db.execute("SELECT summary FROM jobs WHERE job_id=?", (job_id,)).fetchone()
    db.close()
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"summary": row[0]}
