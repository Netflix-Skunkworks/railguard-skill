#!/usr/bin/env python3
"""
scan-progress.py — Track scan progress in SQLite for compaction resilience.

Persists all scan state (phases, agents, findings) to disk so the orchestrator
can resume after context compaction without losing state.

Supports multiple concurrent scans of the same repo. The DB uses WAL mode for
safe concurrent access. Each `init` call creates a new scan row with an
auto-incrementing scan_id. Use `check` before `init` to decide whether to
start a new scan or resume an existing one.

Usage:
  python3 scan-progress.py check --db scan-progress.db
  python3 scan-progress.py list-scans --db scan-progress.db
  python3 scan-progress.py init --db scan-progress.db --repo /path/to/repo --skill-dir /path/to/skill --manifest manifest.txt
  python3 scan-progress.py phase-start --scan-id 1 --phase p2-discovery
  python3 scan-progress.py phase-complete --scan-id 1 --phase p2-discovery --result-file gate-matrix.json
  python3 scan-progress.py agent-dispatch-batch --scan-id 1 --agents-file agents.json
  python3 scan-progress.py agent-result --scan-id 1 --agent database-injection-agent --findings-file findings.json --canary-found '["CANARY:RGS:rule:sql-injection"]'
  python3 scan-progress.py status --latest
  python3 scan-progress.py get-findings --scan-id 1 --phase p3
"""

import argparse
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_path TEXT NOT NULL,
    skill_dir TEXT NOT NULL,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    current_phase TEXT CHECK(current_phase IN (
        'p1-enumerate', 'p2-discovery', 'p2.5-dataflow',
        'p3-dispatch', 'p3-collect', 'p4-validation',
        'p5-report', 'p6-benchmark', 'completed', 'failed'
    )) DEFAULT 'p1-enumerate',
    status TEXT CHECK(status IN ('running', 'completed', 'failed')) DEFAULT 'running',
    total_files INTEGER DEFAULT 0,
    is_large_repo INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    file_path TEXT NOT NULL,
    extension TEXT,
    size_bytes INTEGER,
    UNIQUE(scan_id, file_path)
);

CREATE TABLE IF NOT EXISTS phases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    phase_name TEXT NOT NULL,
    status TEXT CHECK(status IN ('pending', 'in_progress', 'completed', 'failed')) DEFAULT 'pending',
    started_at TEXT,
    completed_at TEXT,
    result_json TEXT,
    UNIQUE(scan_id, phase_name)
);

CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    agent_name TEXT NOT NULL,
    status TEXT CHECK(status IN ('dispatched', 'returned', 'failed', 'skipped')) DEFAULT 'dispatched',
    dispatched_at TEXT,
    returned_at TEXT,
    findings_count INTEGER DEFAULT 0,
    skip_reason TEXT,
    canary_expected TEXT,
    canary_found TEXT,
    canary_status TEXT,
    output_file TEXT,
    UNIQUE(scan_id, agent_name)
);

CREATE TABLE IF NOT EXISTS file_coverage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    file_id INTEGER NOT NULL REFERENCES files(id),
    agent_id INTEGER NOT NULL REFERENCES agents(id),
    UNIQUE(scan_id, file_id, agent_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    agent_id INTEGER REFERENCES agents(id),
    phase TEXT NOT NULL,
    severity TEXT,
    vuln_type TEXT,
    title TEXT,
    file_path TEXT,
    line_start INTEGER,
    line_end INTEGER,
    finding_json TEXT NOT NULL,
    is_final INTEGER DEFAULT 0,
    fp_status TEXT,
    UNIQUE(scan_id, vuln_type, file_path, line_start)
);

CREATE INDEX IF NOT EXISTS idx_files_scan ON files(scan_id);
CREATE INDEX IF NOT EXISTS idx_phases_scan ON phases(scan_id);
CREATE INDEX IF NOT EXISTS idx_agents_scan ON agents(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_phase ON findings(scan_id, phase);
CREATE INDEX IF NOT EXISTS idx_file_coverage_scan ON file_coverage(scan_id);
"""

ALL_PHASES = [
    "p1-enumerate",
    "p2-discovery",
    "p2.5-dataflow",
    "p3-dispatch",
    "p3-collect",
    "p4-validation",
    "p5-report",
    "p6-benchmark",
]


def init_db(db_path: str) -> sqlite3.Connection:
    """Initialize the database, creating tables if they don't exist."""
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def error_exit(msg: str):
    """Print an error message to stderr and exit with code 1."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_manifest(manifest_path: str) -> list[dict]:
    """Parse the enumerate-files.sh manifest into a list of file dicts.

    Manifest lines look like:  ./path/to/file.py (1234 bytes)
    """
    if not os.path.isfile(manifest_path):
        error_exit(f"Manifest file not found: {manifest_path}")

    pattern = re.compile(r"^\s+\./(.+?)\s+\((\d+)\s+bytes\)$")
    files = []

    with open(manifest_path, "r") as f:
        for line in f:
            m = pattern.match(line)
            if m:
                file_path = m.group(1)
                size_bytes = int(m.group(2))
                ext = os.path.splitext(file_path)[1].lstrip(".") or None
                files.append(
                    {
                        "file_path": file_path,
                        "extension": ext,
                        "size_bytes": size_bytes,
                    }
                )

    return files


def resolve_scan_id(conn: sqlite3.Connection, args) -> int:
    """Resolve a scan ID from --scan-id or --latest."""
    if hasattr(args, "latest") and args.latest:
        row = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            error_exit("No scans found in the database")
        return row["id"]
    if hasattr(args, "scan_id") and args.scan_id is not None:
        return args.scan_id
    error_exit("Must provide --scan-id or --latest")


# ---------------------------------------------------------------------------
# Command: init
# ---------------------------------------------------------------------------
def cmd_init(args):
    """Initialize a new scan. Always creates a new row with an auto-incrementing
    scan_id (via AUTOINCREMENT + lastrowid). Safe to call on an existing DB —
    previous scans are preserved. Use the `check` command first to decide whether
    to init a new scan or resume an existing one."""
    conn = init_db(args.db)
    ts = now_iso()

    # Parse manifest
    files = parse_manifest(args.manifest)
    total_files = len(files)
    is_large_repo = 1 if total_files > 200 else 0

    # Create scan row
    cursor = conn.execute(
        """INSERT INTO scans (repo_path, skill_dir, started_at, updated_at,
           current_phase, status, total_files, is_large_repo)
           VALUES (?, ?, ?, ?, 'p1-enumerate', 'running', ?, ?)""",
        (args.repo, args.skill_dir, ts, ts, total_files, is_large_repo),
    )
    scan_id = cursor.lastrowid

    # Insert files
    for fi in files:
        conn.execute(
            """INSERT INTO files (scan_id, file_path, extension, size_bytes)
               VALUES (?, ?, ?, ?)""",
            (scan_id, fi["file_path"], fi["extension"], fi["size_bytes"]),
        )

    # Pre-populate phase rows
    for phase in ALL_PHASES:
        if phase == "p1-enumerate":
            conn.execute(
                """INSERT INTO phases (scan_id, phase_name, status, started_at, completed_at)
                   VALUES (?, ?, 'completed', ?, ?)""",
                (scan_id, phase, ts, ts),
            )
        else:
            conn.execute(
                """INSERT INTO phases (scan_id, phase_name, status)
                   VALUES (?, ?, 'pending')""",
                (scan_id, phase),
            )

    conn.commit()

    result = {
        "scan_id": scan_id,
        "total_files": total_files,
        "is_large_repo": bool(is_large_repo),
    }
    print(json.dumps(result, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: phase-start
# ---------------------------------------------------------------------------
def cmd_phase_start(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)
    ts = now_iso()

    # Verify the phase exists
    row = conn.execute(
        "SELECT id FROM phases WHERE scan_id = ? AND phase_name = ?",
        (scan_id, args.phase),
    ).fetchone()
    if not row:
        error_exit(f"Phase '{args.phase}' not found for scan_id={scan_id}")

    # Update phase to in_progress
    conn.execute(
        """UPDATE phases SET status = 'in_progress', started_at = ?
           WHERE scan_id = ? AND phase_name = ?""",
        (ts, scan_id, args.phase),
    )

    # Update scan current_phase and updated_at
    conn.execute(
        "UPDATE scans SET current_phase = ?, updated_at = ? WHERE id = ?",
        (args.phase, ts, scan_id),
    )

    conn.commit()
    print(json.dumps({"status": "ok", "scan_id": scan_id, "phase": args.phase}, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: phase-complete
# ---------------------------------------------------------------------------
def cmd_phase_complete(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)
    ts = now_iso()

    # Read result file if provided
    result_json = None
    if args.result_file:
        if not os.path.isfile(args.result_file):
            error_exit(f"Result file not found: {args.result_file}")
        with open(args.result_file, "r") as f:
            result_json = f.read()

    # Update phase to completed
    conn.execute(
        """UPDATE phases SET status = 'completed', completed_at = ?, result_json = ?
           WHERE scan_id = ? AND phase_name = ?""",
        (ts, result_json, scan_id, args.phase),
    )

    # Update scan updated_at
    conn.execute(
        "UPDATE scans SET updated_at = ? WHERE id = ?",
        (ts, scan_id),
    )

    conn.commit()
    print(json.dumps({"status": "ok", "scan_id": scan_id, "phase": args.phase}, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: agent-dispatch-batch
# ---------------------------------------------------------------------------
def cmd_agent_dispatch_batch(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)
    ts = now_iso()

    if not os.path.isfile(args.agents_file):
        error_exit(f"Agents file not found: {args.agents_file}")

    with open(args.agents_file, "r") as f:
        agents = json.load(f)

    if not isinstance(agents, list):
        error_exit("Agents file must contain a JSON array")

    dispatched = []
    for agent in agents:
        name = agent.get("name")
        if not name:
            print("WARNING: Skipping agent entry with no name", file=sys.stderr)
            continue

        canary_expected = agent.get("canary_expected")
        canary_json = json.dumps(canary_expected) if canary_expected else None
        output_file = agent.get("output_file")

        conn.execute(
            """INSERT OR REPLACE INTO agents
               (scan_id, agent_name, status, dispatched_at, canary_expected, output_file)
               VALUES (?, ?, 'dispatched', ?, ?, ?)""",
            (scan_id, name, ts, canary_json, output_file),
        )
        dispatched.append(name)

    conn.commit()
    print(json.dumps({"status": "ok", "scan_id": scan_id, "dispatched": dispatched}, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: agent-result
# ---------------------------------------------------------------------------
def cmd_agent_result(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)
    ts = now_iso()

    # Look up the agent
    agent_row = conn.execute(
        "SELECT id, canary_expected FROM agents WHERE scan_id = ? AND agent_name = ?",
        (scan_id, args.agent),
    ).fetchone()
    if not agent_row:
        error_exit(f"Agent '{args.agent}' not found for scan_id={scan_id}")

    agent_id = agent_row["id"]
    canary_expected_raw = agent_row["canary_expected"]

    # Read findings file
    if not os.path.isfile(args.findings_file):
        error_exit(f"Findings file not found: {args.findings_file}")

    with open(args.findings_file, "r") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        error_exit("Findings file must contain a JSON array")

    # Insert findings
    stored = 0
    for finding in findings:
        finding_json = json.dumps(finding)
        severity = finding.get("severity")
        vuln_type = (
            finding.get("type") or finding.get("vulnerability_type") or finding.get("vuln_type")
        )
        title = finding.get("title")
        file_path = finding.get("file") or finding.get("file_path")
        line_start = finding.get("line_start")
        line_end = finding.get("line_end")

        try:
            conn.execute(
                """INSERT OR REPLACE INTO findings
                   (scan_id, agent_id, phase, severity, vuln_type, title,
                    file_path, line_start, line_end, finding_json)
                   VALUES (?, ?, 'p3', ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    agent_id,
                    severity,
                    vuln_type,
                    title,
                    file_path,
                    line_start,
                    line_end,
                    finding_json,
                ),
            )
            stored += 1
        except sqlite3.IntegrityError as e:
            print(f"WARNING: Skipping duplicate finding: {e}", file=sys.stderr)

    # Canary comparison
    canary_found_list = []
    if args.canary_found:
        try:
            canary_found_list = json.loads(args.canary_found)
        except json.JSONDecodeError:
            error_exit(f"Invalid JSON for --canary-found: {args.canary_found}")

    canary_status = None
    if canary_expected_raw:
        try:
            canary_expected_list = json.loads(canary_expected_raw)
        except json.JSONDecodeError:
            canary_expected_list = []

        if canary_expected_list:
            expected_set = set(canary_expected_list)
            found_set = set(canary_found_list)
            if expected_set.issubset(found_set):
                canary_status = "complete"
            else:
                canary_status = "degraded"

    canary_found_json = json.dumps(canary_found_list) if canary_found_list else None

    # Update agent row
    conn.execute(
        """UPDATE agents SET status = 'returned', returned_at = ?,
           findings_count = ?, canary_found = ?, canary_status = ?
           WHERE id = ?""",
        (ts, stored, canary_found_json, canary_status, agent_id),
    )

    # Update scan updated_at
    conn.execute(
        "UPDATE scans SET updated_at = ? WHERE id = ?",
        (ts, scan_id),
    )

    conn.commit()

    result = {
        "stored": stored,
        "canary_status": canary_status or "none",
    }
    print(json.dumps(result, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: agent-skip
# ---------------------------------------------------------------------------
def cmd_agent_skip(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)
    ts = now_iso()

    conn.execute(
        """INSERT OR REPLACE INTO agents
           (scan_id, agent_name, status, dispatched_at, skip_reason)
           VALUES (?, ?, 'skipped', ?, ?)""",
        (scan_id, args.agent, ts, args.reason),
    )

    conn.commit()
    print(
        json.dumps(
            {"status": "ok", "scan_id": scan_id, "agent": args.agent, "skipped": True}, indent=2
        )
    )
    conn.close()


# ---------------------------------------------------------------------------
# Command: store-findings
# ---------------------------------------------------------------------------
def cmd_store_findings(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)

    if not os.path.isfile(args.findings_file):
        error_exit(f"Findings file not found: {args.findings_file}")

    with open(args.findings_file, "r") as f:
        findings = json.load(f)

    if not isinstance(findings, list):
        error_exit("Findings file must contain a JSON array")

    is_final = 1 if args.phase == "p4" else 0

    stored = 0
    for finding in findings:
        finding_json = json.dumps(finding)
        severity = finding.get("severity")
        vuln_type = (
            finding.get("type") or finding.get("vulnerability_type") or finding.get("vuln_type")
        )
        title = finding.get("title")
        file_path = finding.get("file") or finding.get("file_path")
        line_start = finding.get("line_start")
        line_end = finding.get("line_end")
        fp_status = finding.get("fp_status")

        try:
            conn.execute(
                """INSERT OR REPLACE INTO findings
                   (scan_id, phase, severity, vuln_type, title,
                    file_path, line_start, line_end, finding_json, is_final, fp_status)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    args.phase,
                    severity,
                    vuln_type,
                    title,
                    file_path,
                    line_start,
                    line_end,
                    finding_json,
                    is_final,
                    fp_status,
                ),
            )
            stored += 1
        except sqlite3.IntegrityError as e:
            print(f"WARNING: Skipping duplicate finding: {e}", file=sys.stderr)

    conn.commit()

    result = {
        "stored": stored,
        "phase": args.phase,
    }
    print(json.dumps(result, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: check
# ---------------------------------------------------------------------------
def cmd_check(args):
    """Check the DB to decide whether to start a new scan or resume an existing one.

    Output is JSON with an "action" field:
      - "new_scan": caller should run `init` to create a new scan
      - "resume":   caller should resume the returned scan_id
    """
    db_path = args.db

    # Case 1: DB doesn't exist yet
    if not os.path.isfile(db_path):
        print(
            json.dumps(
                {
                    "action": "new_scan",
                    "reason": "no database found",
                },
                indent=2,
            )
        )
        return

    conn = init_db(db_path)

    # Find the most recent scan with status='running'
    row = conn.execute(
        "SELECT * FROM scans WHERE status = 'running' ORDER BY id DESC LIMIT 1"
    ).fetchone()

    if not row:
        # No running scans — recommend starting a new one
        last = conn.execute("SELECT id, status FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        result = {
            "action": "new_scan",
            "reason": "no running scans",
        }
        if last:
            result["last_scan_id"] = last["id"]
            result["last_status"] = last["status"]
        print(json.dumps(result, indent=2))
        conn.close()
        return

    scan = dict(row)

    # Check staleness: if updated_at is more than 2 hours ago, treat as abandoned
    try:
        updated_at = datetime.fromisoformat(scan["updated_at"])
        age_seconds = (datetime.now(timezone.utc) - updated_at).total_seconds()
        if age_seconds > 2 * 3600:
            result = {
                "action": "new_scan",
                "reason": "stale running scan (not updated in >2 hours)",
                "stale_scan_id": scan["id"],
                "last_updated": scan["updated_at"],
                "age_seconds": int(age_seconds),
            }
            print(json.dumps(result, indent=2))
            conn.close()
            return
    except (ValueError, TypeError):
        pass  # If we can't parse the timestamp, fall through to resume

    # Active running scan found — build resume instructions
    phase_rows = conn.execute(
        "SELECT phase_name, status, result_json FROM phases WHERE scan_id = ? ORDER BY id",
        (scan["id"],),
    ).fetchall()
    phases = {}
    for p in phase_rows:
        p = dict(p)
        entry = {"status": p["status"]}
        if p["result_json"] is not None:
            entry["has_result"] = True
        phases[p["phase_name"]] = entry

    agent_rows = conn.execute("SELECT * FROM agents WHERE scan_id = ?", (scan["id"],)).fetchall()

    dispatched_count = 0
    returned_count = 0
    pending_agents = []
    skipped_agents = []

    for a in [dict(a) for a in agent_rows]:
        if a["status"] == "dispatched":
            dispatched_count += 1
            pending_agents.append(a["agent_name"])
        elif a["status"] == "returned":
            dispatched_count += 1
            returned_count += 1
        elif a["status"] == "failed":
            dispatched_count += 1
            pending_agents.append(a["agent_name"])
        elif a["status"] == "skipped":
            skipped_agents.append(a["agent_name"])

    agents_summary = {
        "dispatched": dispatched_count,
        "returned": returned_count,
        "pending": pending_agents,
        "skipped": skipped_agents,
    }

    resume_instructions = _generate_resume_instructions(scan, phases, agents_summary)

    result = {
        "action": "resume",
        "scan_id": scan["id"],
        "current_phase": scan["current_phase"],
        "resume_instructions": resume_instructions,
    }
    print(json.dumps(result, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: list-scans
# ---------------------------------------------------------------------------
def cmd_list_scans(args):
    """List all scans in the database, ordered by scan_id DESC."""
    db_path = args.db

    if not os.path.isfile(db_path):
        error_exit(f"Database not found: {db_path}")

    conn = init_db(db_path)

    rows = conn.execute(
        """SELECT id, repo_path, status, current_phase,
                  started_at, updated_at, total_files
           FROM scans ORDER BY id DESC"""
    ).fetchall()

    scans = []
    for row in rows:
        row = dict(row)
        scans.append(
            {
                "scan_id": row["id"],
                "repo_path": row["repo_path"],
                "status": row["status"],
                "current_phase": row["current_phase"],
                "started_at": row["started_at"],
                "updated_at": row["updated_at"],
                "total_files": row["total_files"],
            }
        )

    print(json.dumps(scans, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: status
# ---------------------------------------------------------------------------
def cmd_status(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)

    # Fetch scan row
    scan = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not scan:
        error_exit(f"Scan not found: scan_id={scan_id}")
    scan = dict(scan)

    # Fetch phases
    phase_rows = conn.execute(
        "SELECT phase_name, status, result_json FROM phases WHERE scan_id = ? ORDER BY id",
        (scan_id,),
    ).fetchall()
    phases = {}
    for p in phase_rows:
        p = dict(p)
        entry = {"status": p["status"]}
        if p["result_json"] is not None:
            entry["has_result"] = True
        phases[p["phase_name"]] = entry

    # Fetch agents
    agent_rows = conn.execute("SELECT * FROM agents WHERE scan_id = ?", (scan_id,)).fetchall()
    agent_rows = [dict(a) for a in agent_rows]

    dispatched_count = 0
    returned_count = 0
    pending_agents = []
    returned_agents = []
    skipped_agents = []

    for a in agent_rows:
        if a["status"] == "dispatched":
            dispatched_count += 1
            pending_agents.append(a["agent_name"])
        elif a["status"] == "returned":
            dispatched_count += 1
            returned_count += 1
            returned_agents.append(
                {
                    "name": a["agent_name"],
                    "findings_count": a["findings_count"],
                    "canary_status": a["canary_status"],
                }
            )
        elif a["status"] == "failed":
            dispatched_count += 1
            pending_agents.append(a["agent_name"])
        elif a["status"] == "skipped":
            skipped_agents.append(a["agent_name"])

    agents_summary = {
        "dispatched": dispatched_count,
        "returned": returned_count,
        "pending": pending_agents,
        "returned_agents": returned_agents,
        "skipped": skipped_agents,
    }

    # Findings summary
    total_p3 = conn.execute(
        "SELECT COUNT(*) as cnt FROM findings WHERE scan_id = ? AND phase = 'p3'",
        (scan_id,),
    ).fetchone()["cnt"]

    total_p4_final = conn.execute(
        "SELECT COUNT(*) as cnt FROM findings WHERE scan_id = ? AND phase = 'p4' AND is_final = 1",
        (scan_id,),
    ).fetchone()["cnt"]

    severity_rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM findings WHERE scan_id = ? AND phase = 'p3' GROUP BY severity",
        (scan_id,),
    ).fetchall()
    by_severity = {}
    for sr in severity_rows:
        sr = dict(sr)
        sev = sr["severity"] or "UNKNOWN"
        by_severity[sev] = sr["cnt"]

    findings_summary = {
        "total_p3": total_p3,
        "total_p4_final": total_p4_final,
        "by_severity": by_severity,
    }

    # File coverage
    total_files = scan["total_files"]
    covered = conn.execute(
        "SELECT COUNT(DISTINCT file_id) as cnt FROM file_coverage WHERE scan_id = ?",
        (scan_id,),
    ).fetchone()["cnt"]
    coverage_pct = round((covered / total_files * 100), 1) if total_files > 0 else 0.0

    file_coverage = {
        "total_files": total_files,
        "covered": covered,
        "coverage_pct": coverage_pct,
    }

    # Generate resume instructions
    resume_instructions = _generate_resume_instructions(scan, phases, agents_summary)

    result = {
        "scan_id": scan_id,
        "repo_path": scan["repo_path"],
        "skill_dir": scan["skill_dir"],
        "current_phase": scan["current_phase"],
        "is_large_repo": bool(scan["is_large_repo"]),
        "total_files": total_files,
        "phases": phases,
        "agents": agents_summary,
        "findings_summary": findings_summary,
        "file_coverage": file_coverage,
        "resume_instructions": resume_instructions,
    }

    print(json.dumps(result, indent=2))
    conn.close()


def _generate_resume_instructions(scan: dict, phases: dict, agents: dict) -> str:
    """Generate human-readable resume instructions based on current state."""
    status = scan["status"]
    current_phase = scan["current_phase"]

    if status == "completed":
        return "Scan completed successfully. No further action needed."
    if status == "failed":
        return f"Scan failed during phase '{current_phase}'. Investigate the failure and consider re-running."

    # Find the current in-progress phase
    in_progress_phases = [name for name, info in phases.items() if info["status"] == "in_progress"]
    pending_phases = [name for name, info in phases.items() if info["status"] == "pending"]
    pending_agents = agents.get("pending", [])
    returned_count = agents.get("returned", 0)
    dispatched_count = agents.get("dispatched", 0)

    parts = []

    if in_progress_phases:
        phase_str = ", ".join(in_progress_phases)
        parts.append(f"Phase {phase_str} in progress.")

    if current_phase in ("p3-collect", "p3-dispatch") and pending_agents:
        agent_str = ", ".join(pending_agents)
        parts.append(f"{len(pending_agents)} agents still pending: {agent_str}.")
        parts.append("Wait for these agents or re-dispatch if they failed.")
    elif current_phase in ("p3-collect",) and not pending_agents and dispatched_count > 0:
        parts.append(f"All {returned_count} agents have returned.")
        parts.append("Complete p3-collect and proceed to p4-validation.")
    elif current_phase == "p4-validation":
        parts.append(
            "Run FP/dedup validation on p3 findings, then store final findings with phase=p4."
        )
    elif current_phase == "p5-report":
        parts.append("Generate the final security report from validated findings.")
    elif current_phase == "p6-benchmark":
        parts.append("Run benchmark comparison against answer sheet if available.")
    elif in_progress_phases:
        next_idx = None
        for ip in in_progress_phases:
            if ip in ALL_PHASES:
                idx = ALL_PHASES.index(ip)
                if next_idx is None or idx > next_idx:
                    next_idx = idx
        if next_idx is not None and next_idx + 1 < len(ALL_PHASES):
            next_phase = ALL_PHASES[next_idx + 1]
            parts.append(f"Once current phase completes, proceed to {next_phase}.")
    elif pending_phases:
        parts.append(f"Next pending phase: {pending_phases[0]}.")

    if not parts:
        parts.append(f"Current phase: {current_phase}. Check phase statuses for next steps.")

    return " ".join(parts)


# ---------------------------------------------------------------------------
# Command: get-phase-result
# ---------------------------------------------------------------------------
def cmd_get_phase_result(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)

    row = conn.execute(
        "SELECT result_json FROM phases WHERE scan_id = ? AND phase_name = ?",
        (scan_id, args.phase),
    ).fetchone()

    if not row or row["result_json"] is None:
        print("null")
    else:
        # Parse and re-dump to ensure valid JSON formatting
        try:
            parsed = json.loads(row["result_json"])
            print(json.dumps(parsed, indent=2))
        except json.JSONDecodeError:
            # If it's not valid JSON, output as raw string
            print(row["result_json"])

    conn.close()


# ---------------------------------------------------------------------------
# Command: get-findings
# ---------------------------------------------------------------------------
def cmd_get_findings(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)

    if args.phase == "p3":
        rows = conn.execute(
            "SELECT finding_json FROM findings WHERE scan_id = ? AND phase = 'p3'",
            (scan_id,),
        ).fetchall()
    elif args.phase == "p4":
        rows = conn.execute(
            "SELECT finding_json FROM findings WHERE scan_id = ? AND phase = 'p4' AND is_final = 1",
            (scan_id,),
        ).fetchall()
    else:
        error_exit(f"Invalid phase for get-findings: {args.phase}. Must be 'p3' or 'p4'.")

    results = []
    for row in rows:
        try:
            results.append(json.loads(row["finding_json"]))
        except json.JSONDecodeError:
            results.append({"raw": row["finding_json"]})

    print(json.dumps(results, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# Command: get-uncovered-files
# ---------------------------------------------------------------------------
def cmd_get_uncovered_files(args):
    conn = init_db(args.db)
    scan_id = resolve_scan_id(conn, args)

    rows = conn.execute(
        """SELECT f.file_path FROM files f
           WHERE f.scan_id = ?
           AND f.id NOT IN (
               SELECT DISTINCT fc.file_id FROM file_coverage fc WHERE fc.scan_id = ?
           )
           ORDER BY f.file_path""",
        (scan_id, scan_id),
    ).fetchall()

    results = [row["file_path"] for row in rows]
    print(json.dumps(results, indent=2))
    conn.close()


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------
def add_db_arg(parser: argparse.ArgumentParser):
    """Add the common --db argument to a subcommand parser."""
    parser.add_argument(
        "--db", default="scan-progress.db", help="SQLite database path (default: scan-progress.db)"
    )


def add_scan_id_args(parser: argparse.ArgumentParser):
    """Add --scan-id and --latest arguments to a subcommand parser."""
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan-id", type=int, help="Scan ID")
    group.add_argument("--latest", action="store_true", help="Use the most recent scan")


def main():
    parser = argparse.ArgumentParser(
        description="Track scan progress in SQLite for compaction resilience"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # check
    p_check = sub.add_parser("check", help="Check DB to decide: new scan or resume existing")
    add_db_arg(p_check)

    # list-scans
    p_list = sub.add_parser("list-scans", help="List all scans in the database")
    add_db_arg(p_list)

    # init
    p_init = sub.add_parser("init", help="Initialize a new scan from a file manifest")
    add_db_arg(p_init)
    p_init.add_argument("--repo", required=True, help="Path to the repository being scanned")
    p_init.add_argument("--skill-dir", required=True, help="Path to the skill directory")
    p_init.add_argument(
        "--manifest", required=True, help="Path to enumerate-files.sh output manifest"
    )

    # phase-start
    p_phase_start = sub.add_parser("phase-start", help="Mark a phase as in-progress")
    add_db_arg(p_phase_start)
    add_scan_id_args(p_phase_start)
    p_phase_start.add_argument("--phase", required=True, help="Phase name (e.g. p2-discovery)")

    # phase-complete
    p_phase_complete = sub.add_parser("phase-complete", help="Mark a phase as completed")
    add_db_arg(p_phase_complete)
    add_scan_id_args(p_phase_complete)
    p_phase_complete.add_argument("--phase", required=True, help="Phase name (e.g. p2-discovery)")
    p_phase_complete.add_argument("--result-file", help="Path to JSON file with phase result data")

    # agent-dispatch-batch
    p_dispatch = sub.add_parser("agent-dispatch-batch", help="Record a batch of dispatched agents")
    add_db_arg(p_dispatch)
    add_scan_id_args(p_dispatch)
    p_dispatch.add_argument(
        "--agents-file", required=True, help="Path to JSON file with agent array"
    )

    # agent-result
    p_result = sub.add_parser("agent-result", help="Record an agent's findings")
    add_db_arg(p_result)
    add_scan_id_args(p_result)
    p_result.add_argument("--agent", required=True, help="Agent name")
    p_result.add_argument(
        "--findings-file", required=True, help="Path to JSON file with findings array"
    )
    p_result.add_argument("--canary-found", help="JSON array string of found canary tokens")

    # agent-skip
    p_skip = sub.add_parser("agent-skip", help="Record an agent as skipped")
    add_db_arg(p_skip)
    add_scan_id_args(p_skip)
    p_skip.add_argument("--agent", required=True, help="Agent name")
    p_skip.add_argument("--reason", required=True, help="Reason for skipping")

    # store-findings
    p_store = sub.add_parser("store-findings", help="Store findings from a phase")
    add_db_arg(p_store)
    add_scan_id_args(p_store)
    p_store.add_argument("--phase", required=True, help="Phase name (p3 or p4)")
    p_store.add_argument(
        "--findings-file", required=True, help="Path to JSON file with findings array"
    )

    # status
    p_status = sub.add_parser("status", help="Show comprehensive scan status")
    add_db_arg(p_status)
    add_scan_id_args(p_status)

    # get-phase-result
    p_get_phase = sub.add_parser("get-phase-result", help="Get stored result for a phase")
    add_db_arg(p_get_phase)
    add_scan_id_args(p_get_phase)
    p_get_phase.add_argument("--phase", required=True, help="Phase name")

    # get-findings
    p_get_findings = sub.add_parser("get-findings", help="Get findings for a phase")
    add_db_arg(p_get_findings)
    add_scan_id_args(p_get_findings)
    p_get_findings.add_argument("--phase", required=True, help="Phase name (p3 or p4)")

    # get-uncovered-files
    p_uncovered = sub.add_parser("get-uncovered-files", help="Get files with no agent coverage")
    add_db_arg(p_uncovered)
    add_scan_id_args(p_uncovered)

    args = parser.parse_args()

    commands = {
        "check": cmd_check,
        "list-scans": cmd_list_scans,
        "init": cmd_init,
        "phase-start": cmd_phase_start,
        "phase-complete": cmd_phase_complete,
        "agent-dispatch-batch": cmd_agent_dispatch_batch,
        "agent-result": cmd_agent_result,
        "agent-skip": cmd_agent_skip,
        "store-findings": cmd_store_findings,
        "status": cmd_status,
        "get-phase-result": cmd_get_phase_result,
        "get-findings": cmd_get_findings,
        "get-uncovered-files": cmd_get_uncovered_files,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        error_exit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
