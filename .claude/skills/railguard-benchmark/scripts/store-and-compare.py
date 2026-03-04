#!/usr/bin/env python3
"""
store-and-compare.py — Store scan findings to SQLite and compare against answer sheets or other runs.

Usage:
  # Store findings from a scan
  python3 store-and-compare.py store --db scans.db --repo /path/to/repo --findings findings.json [--scan-type orchestrated] [--model claude-sonnet-4-5]

  # Compare a stored scan against an answer sheet
  python3 store-and-compare.py compare --db scans.db --run-id 1 --answer-sheet answer-sheet.md

  # Compare two scan runs against each other
  python3 store-and-compare.py compare-runs --db scans.db --run-a 1 --run-b 2

  # List all stored scan runs
  python3 store-and-compare.py list --db scans.db
"""

import argparse
import json
import re
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

LINE_TOLERANCE = 5

SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_path TEXT NOT NULL,
    scan_type TEXT DEFAULT 'skill',
    model TEXT,
    scanned_at TEXT NOT NULL,
    duration_seconds REAL,
    gate_matrix TEXT,
    total_findings INTEGER DEFAULT 0,
    total_files INTEGER,
    languages TEXT,
    frameworks TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS scan_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    severity TEXT NOT NULL,
    vulnerability_type TEXT,
    title TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    file_path TEXT NOT NULL,
    line_start INTEGER,
    line_end INTEGER,
    code_snippet TEXT,
    vulnerability_trace TEXT,
    remediation TEXT,
    triage_tier INTEGER,
    triage_reason TEXT,
    triage_factors TEXT,
    reproduction_steps TEXT,
    is_false_positive INTEGER DEFAULT 0,
    fp_reason TEXT,
    fp_category TEXT,
    corroborated INTEGER DEFAULT 0,
    corroborated_by TEXT,
    detector TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS comparisons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES scan_runs(id),
    answer_sheet_path TEXT,
    compared_against_run_id INTEGER REFERENCES scan_runs(id),
    compared_at TEXT NOT NULL,
    total_expected INTEGER DEFAULT 0,
    total_found INTEGER DEFAULT 0,
    true_positives INTEGER DEFAULT 0,
    false_negatives INTEGER DEFAULT 0,
    extra_findings INTEGER DEFAULT 0,
    precision_score REAL,
    recall_score REAL,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS comparison_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comparison_id INTEGER NOT NULL REFERENCES comparisons(id),
    entry_id TEXT,
    status TEXT NOT NULL,
    matched_finding_id INTEGER REFERENCES scan_findings(id),
    answer_severity TEXT,
    found_severity TEXT,
    answer_type TEXT,
    found_type TEXT,
    answer_file TEXT,
    found_file TEXT,
    answer_line TEXT,
    found_line TEXT,
    answer_category TEXT,
    expected_detection TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS extra_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    comparison_id INTEGER NOT NULL REFERENCES comparisons(id),
    finding_id INTEGER NOT NULL REFERENCES scan_findings(id),
    classification TEXT,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_findings_run ON scan_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_findings_file ON scan_findings(file_path);
CREATE INDEX IF NOT EXISTS idx_comparisons_run ON comparisons(run_id);
CREATE INDEX IF NOT EXISTS idx_comparison_items_comp ON comparison_items(comparison_id);
"""


MIGRATION_COLUMNS = [
    ("duration_ms", "INTEGER"),
    ("input_tokens", "INTEGER"),
    ("output_tokens", "INTEGER"),
    ("cost_usd", "REAL"),
    ("files_analyzed", "INTEGER"),
    ("flows_traced", "INTEGER"),
    ("subagent_count", "INTEGER"),
    ("costs", "REAL"),
]


def init_db(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    for col_name, col_type in MIGRATION_COLUMNS:
        try:
            conn.execute(f"ALTER TABLE scan_runs ADD COLUMN {col_name} {col_type}")
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.commit()
    return conn


def normalize_repo(path: str) -> str:
    """Extract repo name from path variants.

    repos/pixel-vault -> pixel-vault
    /path/to/repo/repos/my-target-repo -> pixel-vault
    """
    if "/repos/" in path:
        return path.split("/repos/")[-1].rstrip("/")
    return Path(path).name


def _short_model(model: str | None) -> str:
    if not model:
        return "--"
    prefixes = ("claude-", "anthropic-")
    m = model
    for p in prefixes:
        if m.startswith(p):
            m = m[len(p) :]
    return m


def _fmt_tokens(n) -> str:
    if n is None:
        return "--"
    n = int(n)
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n / 1_000:.1f}K"
    return str(n)


def cmd_store(args):
    conn = init_db(args.db)

    with open(args.findings) as f:
        data = json.load(f)

    findings = data if isinstance(data, list) else data.get("findings", [])

    now = datetime.now(timezone.utc).isoformat()

    cursor = conn.execute(
        """INSERT INTO scan_runs (repo_path, scan_type, model, scanned_at, total_findings, notes,
               duration_ms, input_tokens, output_tokens, cost_usd, files_analyzed, flows_traced, subagent_count)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            args.repo,
            args.scan_type,
            args.model,
            now,
            len(findings),
            args.notes,
            getattr(args, "duration_ms", None),
            getattr(args, "input_tokens", None),
            getattr(args, "output_tokens", None),
            getattr(args, "cost_usd", None),
            getattr(args, "files_analyzed", None),
            getattr(args, "flows_traced", None),
            getattr(args, "subagent_count", None),
        ),
    )
    run_id = cursor.lastrowid

    for f in findings:
        conn.execute(
            """INSERT INTO scan_findings
               (run_id, severity, vulnerability_type, title, description, impact,
                file_path, line_start, line_end, code_snippet, vulnerability_trace,
                remediation, triage_tier, triage_reason, triage_factors,
                reproduction_steps, is_false_positive, fp_reason, fp_category,
                corroborated, corroborated_by, detector, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                run_id,
                f.get("severity", "MEDIUM"),
                f.get("type") or f.get("vulnerability_type"),
                f.get("title", "Untitled"),
                f.get("description"),
                f.get("impact"),
                f.get("file") or f.get("file_path", ""),
                f.get("line_start"),
                f.get("line_end"),
                f.get("code_snippet"),
                json.dumps(f.get("vulnerability_trace")) if f.get("vulnerability_trace") else None,
                json.dumps(f.get("remediation"))
                if isinstance(f.get("remediation"), dict)
                else f.get("remediation"),
                f.get("triage", {}).get("tier")
                if isinstance(f.get("triage"), dict)
                else f.get("triage_tier"),
                f.get("triage", {}).get("reason")
                if isinstance(f.get("triage"), dict)
                else f.get("triage_reason"),
                json.dumps(f.get("triage", {}).get("factors"))
                if isinstance(f.get("triage"), dict)
                else None,
                json.dumps(f.get("triage", {}).get("reproduction_steps"))
                if isinstance(f.get("triage"), dict)
                else None,
                1 if f.get("is_false_positive") else 0,
                f.get("fp_reason"),
                f.get("fp_category"),
                1 if f.get("corroborated") else 0,
                f.get("corroborated_by"),
                f.get("detector"),
                now,
            ),
        )

    conn.commit()
    print(
        json.dumps(
            {
                "status": "stored",
                "run_id": run_id,
                "findings_count": len(findings),
                "db": args.db,
            },
            indent=2,
        )
    )
    conn.close()


def parse_answer_sheet(path: str) -> list[dict]:
    """Parse a markdown answer sheet in flat table format into structured entries.

    Expected columns (order flexible, matched by header):
      ID | Agent | Type | Category | File | Line | Function/Route | Severity | Detection | Description

    The canonical column-to-field mapping:
      id, agent, vulnerability_type, category, file, line_range,
      function/route, expected_severity, expected_detection, description
    """
    content = Path(path).read_text()
    entries = []

    # Find the header row of the vulnerability catalog table
    header_match = re.search(
        r"^\|(.+)\|$",
        content,
        flags=re.MULTILINE,
    )
    if not header_match:
        return entries

    # Locate the full table: header + separator + data rows
    table_pattern = re.compile(
        r"^(\|.+\|)\n\|[-| :]+\|\n((?:\|.+\|\n?)*)",
        flags=re.MULTILINE,
    )

    for table_match in table_pattern.finditer(content):
        raw_header = table_match.group(1)
        raw_rows = table_match.group(2)

        # Parse header columns
        headers = [h.strip().lower().replace(" ", "_").replace("/", "_") for h in raw_header.strip("|").split("|")]

        # Skip summary/coverage tables (no "id" column, or first column not matching an ID pattern)
        if "id" not in headers:
            continue

        id_idx = headers.index("id")

        # Parse each data row
        for row_line in raw_rows.strip().splitlines():
            if not row_line.strip().startswith("|"):
                continue
            cells = [c.strip() for c in row_line.strip("|").split("|")]
            if len(cells) < len(headers):
                continue

            # Must look like a vulnerability ID (e.g. PV-001, XL-001, PVJ-001)
            entry_id = cells[id_idx].strip()
            if not re.match(r"^[A-Z]+-\d+$", entry_id):
                continue

            entry: dict = {}
            for i, col in enumerate(headers):
                if i < len(cells):
                    val = cells[i].strip().strip("`")
                    entry[col] = val

            # Normalise column names to the keys find_match() expects
            rename = {
                "type": "vulnerability_type",
                "line": "line_range",
                "severity": "expected_severity",
                "detection": "expected_detection",
                "function_route": "function_route",
            }
            for old, new in rename.items():
                if old in entry and new not in entry:
                    entry[new] = entry.pop(old)

            entries.append(entry)

        # Only process the first matching catalog table
        if entries:
            break

    return entries


def find_match(entry: dict, findings: list[dict]) -> tuple[dict | None, str]:
    """Find the best matching finding for an answer sheet entry.

    Returns (matched_finding_or_None, match_quality).
    match_quality: 'exact', 'partial', 'type_only', or 'none'
    """
    entry_file = entry.get("file", "").strip("/")
    entry_line = entry.get("line_range", "")
    entry_type = (entry.get("vulnerability_type") or entry.get("agent", "")).lower()

    try:
        entry_line_start = int(re.search(r"\d+", str(entry_line)).group()) if entry_line else 0
    except (AttributeError, ValueError):
        entry_line_start = 0

    best_match = None
    best_quality = "none"

    for f in findings:
        f_file = (f.get("file_path") or f.get("file") or "").strip("/")
        f_type = (f.get("vulnerability_type") or f.get("type") or "").lower()
        f_line_start = f.get("line_start") or 0

        file_match = (
            f_file.endswith(entry_file) or entry_file.endswith(f_file)
            if (entry_file and f_file)
            else False
        )

        type_aliases = {
            "hardcoded_secret": {"secrets", "hardcoded_secret", "secret", "information_disclosure"},
            "secrets": {"secrets", "hardcoded_secret", "secret", "information_disclosure"},
            "information_disclosure": {
                "secrets",
                "hardcoded_secret",
                "secret",
                "information_disclosure",
            },
            "sqli": {"sqli", "sql_injection"},
            "nosqli": {"nosqli", "nosql_injection"},
            "xss": {
                "xss",
                "cross_site_scripting",
                "reflected_xss",
                "stored_xss",
                "dom_xss",
                "xss_reflected",
                "xss_stored",
                "xss_dom",
            },
            "xss_reflected": {"xss", "xss_reflected", "reflected_xss", "cross_site_scripting"},
            "xss_stored": {"xss", "xss_stored", "stored_xss", "cross_site_scripting"},
            "xss_dom": {"xss", "xss_dom", "dom_xss", "cross_site_scripting"},
            "reflected_xss": {"xss", "xss_reflected", "reflected_xss", "cross_site_scripting"},
            "stored_xss": {"xss", "xss_stored", "stored_xss", "cross_site_scripting"},
            "dom_xss": {"xss", "xss_dom", "dom_xss", "cross_site_scripting"},
            "ssti": {"ssti", "template_injection", "server_side_template_injection"},
            "ssrf": {"ssrf", "server_side_request_forgery"},
            "xxe": {"xxe", "xml_external_entity"},
            "path_traversal": {"path_traversal", "directory_traversal", "file_upload"},
            "file_upload": {"file_upload", "unrestricted_upload", "path_traversal"},
            "deserialization": {"deserialization", "insecure_deserialization"},
            "command_injection": {"command_injection", "os_command_injection", "code_injection"},
            "code_injection": {"code_injection", "command_injection", "os_command_injection"},
            "authentication": {
                "authentication",
                "auth_bypass",
                "weak_auth",
                "authentication_bypass",
                "weak_cryptography",
                "session_fixation",
            },
            "authentication_bypass": {
                "authentication",
                "authentication_bypass",
                "auth_bypass",
                "weak_auth",
            },
            "weak_cryptography": {"authentication", "weak_cryptography", "weak_auth"},
            "session_fixation": {"authentication", "session_fixation", "weak_auth"},
            "authorization": {
                "authorization",
                "idor",
                "broken_access_control",
                "privilege_escalation",
                "authorization_bypass",
            },
            "privilege_escalation": {
                "authorization",
                "privilege_escalation",
                "broken_access_control",
            },
            "authorization_bypass": {
                "authorization",
                "authorization_bypass",
                "broken_access_control",
            },
            "github_actions": {"github_actions", "ci_cd", "cicd"},
            "race_condition": {"race_condition", "toctou", "logic_vulnerability"},
            "logic_vulnerability": {
                "logic",
                "logic_vulnerability",
                "business_logic",
                "logic_vulnerabilities",
                "race_condition",
                "authorization",
            },
            "prototype_pollution": {"prototype_pollution"},
            "cors": {"cors", "cors_misconfiguration"},
            "prompt_injection": {"prompt_injection", "llm_injection"},
            "logic": {"logic", "business_logic", "logic_vulnerabilities", "logic_vulnerability"},
            "input_validation": {"input_validation"},
        }

        entry_type_set = type_aliases.get(entry_type, {entry_type})
        f_type_set = type_aliases.get(f_type, {f_type})
        type_match = bool(entry_type_set & f_type_set)

        line_close = (
            abs(f_line_start - entry_line_start) <= LINE_TOLERANCE
            if (entry_line_start and f_line_start)
            else False
        )

        if file_match and type_match and line_close:
            if best_quality != "exact":
                best_match = f
                best_quality = "exact"
        elif file_match and type_match:
            if best_quality not in ("exact",):
                best_match = f
                best_quality = "partial"
        elif file_match and line_close:
            if best_quality not in ("exact", "partial"):
                best_match = f
                best_quality = "partial"
        elif type_match and f_file and entry_file and Path(f_file).name == Path(entry_file).name:
            if best_quality == "none":
                best_match = f
                best_quality = "type_only"

    return best_match, best_quality


def cmd_compare(args):
    conn = init_db(args.db)

    findings_rows = conn.execute(
        "SELECT * FROM scan_findings WHERE run_id = ?", (args.run_id,)
    ).fetchall()
    findings = [dict(r) for r in findings_rows]

    if not findings:
        print(f"ERROR: No findings found for run_id={args.run_id}", file=sys.stderr)
        sys.exit(1)

    entries = parse_answer_sheet(args.answer_sheet)
    if not entries:
        print(f"ERROR: No entries parsed from {args.answer_sheet}", file=sys.stderr)
        sys.exit(1)

    now = datetime.now(timezone.utc).isoformat()

    matched_finding_ids = set()
    items = []
    tp = 0
    fn = 0

    for entry in entries:
        expected = entry.get("expected_detection", "YES").upper()
        category = entry.get("category", "active").lower()
        match, quality = find_match(entry, findings)

        if match and quality in ("exact", "partial"):
            status = "matched" if quality == "exact" else "partial"
            matched_finding_ids.add(match["id"])
            if expected == "YES":
                tp += 1
            items.append(
                {
                    "entry_id": entry.get("id"),
                    "status": status,
                    "matched_finding_id": match["id"],
                    "answer_severity": entry.get("expected_severity"),
                    "found_severity": match.get("severity"),
                    "answer_type": entry.get("vulnerability_type") or entry.get("agent"),
                    "found_type": match.get("vulnerability_type"),
                    "answer_file": entry.get("file"),
                    "found_file": match.get("file_path"),
                    "answer_line": str(entry.get("line_range", "")),
                    "found_line": f"{match.get('line_start', '')}-{match.get('line_end', '')}",
                    "answer_category": category,
                    "expected_detection": expected,
                    "notes": None,
                }
            )
        elif match and quality == "type_only":
            if expected == "YES":
                fn += 1
            items.append(
                {
                    "entry_id": entry.get("id"),
                    "status": "partial",
                    "matched_finding_id": match["id"],
                    "answer_severity": entry.get("expected_severity"),
                    "found_severity": match.get("severity"),
                    "answer_type": entry.get("vulnerability_type") or entry.get("agent"),
                    "found_type": match.get("vulnerability_type"),
                    "answer_file": entry.get("file"),
                    "found_file": match.get("file_path"),
                    "answer_line": str(entry.get("line_range", "")),
                    "found_line": f"{match.get('line_start', '')}-{match.get('line_end', '')}",
                    "answer_category": category,
                    "expected_detection": expected,
                    "notes": "Weak match: same type but different file/location",
                }
            )
        elif expected == "NO":
            items.append(
                {
                    "entry_id": entry.get("id"),
                    "status": "correctly_not_found",
                    "matched_finding_id": None,
                    "answer_severity": entry.get("expected_severity"),
                    "found_severity": None,
                    "answer_type": entry.get("vulnerability_type") or entry.get("agent"),
                    "found_type": None,
                    "answer_file": entry.get("file"),
                    "found_file": None,
                    "answer_line": str(entry.get("line_range", "")),
                    "found_line": None,
                    "answer_category": category,
                    "expected_detection": expected,
                    "notes": "FP bait correctly not flagged" if category == "fp-bait" else None,
                }
            )
        else:
            fn += 1
            items.append(
                {
                    "entry_id": entry.get("id"),
                    "status": "missed",
                    "matched_finding_id": None,
                    "answer_severity": entry.get("expected_severity"),
                    "found_severity": None,
                    "answer_type": entry.get("vulnerability_type") or entry.get("agent"),
                    "found_type": None,
                    "answer_file": entry.get("file"),
                    "found_file": None,
                    "answer_line": str(entry.get("line_range", "")),
                    "found_line": None,
                    "answer_category": category,
                    "expected_detection": expected,
                    "notes": None,
                }
            )

    extra = [
        f for f in findings if f["id"] not in matched_finding_ids and not f.get("is_false_positive")
    ]
    total_expected = sum(1 for e in entries if e.get("expected_detection", "YES").upper() == "YES")
    precision = tp / (tp + len(extra)) if (tp + len(extra)) > 0 else 0.0
    recall = tp / total_expected if total_expected > 0 else 0.0

    cursor = conn.execute(
        """INSERT INTO comparisons
           (run_id, answer_sheet_path, compared_at, total_expected, total_found,
            true_positives, false_negatives, extra_findings, precision_score, recall_score)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            args.run_id,
            args.answer_sheet,
            now,
            total_expected,
            len(findings),
            tp,
            fn,
            len(extra),
            round(precision, 4),
            round(recall, 4),
        ),
    )
    comparison_id = cursor.lastrowid

    for item in items:
        conn.execute(
            """INSERT INTO comparison_items
               (comparison_id, entry_id, status, matched_finding_id,
                answer_severity, found_severity, answer_type, found_type,
                answer_file, found_file, answer_line, found_line,
                answer_category, expected_detection, notes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                comparison_id,
                item["entry_id"],
                item["status"],
                item["matched_finding_id"],
                item["answer_severity"],
                item["found_severity"],
                item["answer_type"],
                item["found_type"],
                item["answer_file"],
                item["found_file"],
                item["answer_line"],
                item["found_line"],
                item["answer_category"],
                item["expected_detection"],
                item["notes"],
            ),
        )

    for ef in extra:
        conn.execute(
            "INSERT INTO extra_findings (comparison_id, finding_id) VALUES (?, ?)",
            (comparison_id, ef["id"]),
        )

    conn.commit()

    result = {
        "comparison_id": comparison_id,
        "run_id": args.run_id,
        "answer_sheet": args.answer_sheet,
        "summary": {
            "total_expected": total_expected,
            "total_scan_findings": len(findings),
            "true_positives": tp,
            "false_negatives": fn,
            "extra_findings": len(extra),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
        },
        "items": items,
        "extra_findings": [
            {
                "finding_id": ef["id"],
                "severity": ef.get("severity"),
                "type": ef.get("vulnerability_type"),
                "title": ef.get("title"),
                "file": ef.get("file_path"),
                "line": f"{ef.get('line_start', '')}-{ef.get('line_end', '')}",
            }
            for ef in extra
        ],
    }

    print(json.dumps(result, indent=2))
    conn.close()


def cmd_compare_runs(args):
    conn = init_db(args.db)

    run_a_meta = conn.execute(
        "SELECT id, repo_path, scan_type, model, scanned_at, total_findings FROM scan_runs WHERE id = ?",
        (args.run_a,),
    ).fetchone()
    run_b_meta = conn.execute(
        "SELECT id, repo_path, scan_type, model, scanned_at, total_findings FROM scan_runs WHERE id = ?",
        (args.run_b,),
    ).fetchone()

    findings_a = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM scan_findings WHERE run_id = ?", (args.run_a,)
        ).fetchall()
    ]
    findings_b = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM scan_findings WHERE run_id = ?", (args.run_b,)
        ).fetchall()
    ]

    if not findings_a:
        print(f"ERROR: No findings for run_id={args.run_a}", file=sys.stderr)
        sys.exit(1)
    if not findings_b:
        print(f"ERROR: No findings for run_id={args.run_b}", file=sys.stderr)
        sys.exit(1)

    common_pairs, only_a_raw, only_b_raw = _match_findings_across_runs(findings_a, findings_b)

    common = [
        {
            "file": fa.get("file_path"),
            "type": fa.get("vulnerability_type"),
            "severity_a": fa.get("severity"),
            "severity_b": fb.get("severity"),
            "line_a": fa.get("line_start"),
            "line_b": fb.get("line_start"),
            "title_a": fa.get("title"),
            "title_b": fb.get("title"),
        }
        for fa, fb in common_pairs
    ]

    only_a = [
        {
            "file": f.get("file_path"),
            "type": f.get("vulnerability_type"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "line": f.get("line_start"),
        }
        for f in only_a_raw
    ]

    only_b = [
        {
            "file": f.get("file_path"),
            "type": f.get("vulnerability_type"),
            "severity": f.get("severity"),
            "title": f.get("title"),
            "line": f.get("line_start"),
        }
        for f in only_b_raw
    ]

    result = {
        "run_a": {
            "id": args.run_a,
            "scan_type": dict(run_a_meta).get("scan_type") if run_a_meta else None,
            "model": dict(run_a_meta).get("model") if run_a_meta else None,
            "scanned_at": dict(run_a_meta).get("scanned_at") if run_a_meta else None,
        },
        "run_b": {
            "id": args.run_b,
            "scan_type": dict(run_b_meta).get("scan_type") if run_b_meta else None,
            "model": dict(run_b_meta).get("model") if run_b_meta else None,
            "scanned_at": dict(run_b_meta).get("scanned_at") if run_b_meta else None,
        },
        "summary": {
            "findings_in_a": len(findings_a),
            "findings_in_b": len(findings_b),
            "common": len(common),
            "only_in_a": len(only_a),
            "only_in_b": len(only_b),
        },
        "common_findings": common,
        "only_in_run_a": only_a,
        "only_in_run_b": only_b,
    }

    print(json.dumps(result, indent=2))
    conn.close()


def cmd_list(args):
    conn = init_db(args.db)
    rows = conn.execute(
        "SELECT id, repo_path, scan_type, model, scanned_at, total_findings, notes FROM scan_runs ORDER BY id"
    ).fetchall()

    runs = [dict(r) for r in rows]
    print(json.dumps(runs, indent=2))
    conn.close()


def _compute_dashboard_metrics(conn, run_id, comparison_id):
    """Compute derived metrics for a single run/comparison pair."""
    # Severity accuracy
    row = conn.execute(
        """SELECT COUNT(*) as total,
                  SUM(CASE WHEN UPPER(answer_severity) = UPPER(found_severity) THEN 1 ELSE 0 END) as match
           FROM comparison_items WHERE comparison_id = ? AND status IN ('matched','partial') AND found_severity IS NOT NULL""",
        (comparison_id,),
    ).fetchone()
    sev_total, sev_match = row["total"], row["match"]
    sev_acc = f"{sev_match / sev_total * 100:.1f}%" if sev_total > 0 else "--"

    # FP bait
    row = conn.execute(
        """SELECT SUM(CASE WHEN status='correctly_not_found' THEN 1 ELSE 0 END) as avoided, COUNT(*) as total
           FROM comparison_items WHERE comparison_id = ? AND answer_category = 'false-positive-bait'""",
        (comparison_id,),
    ).fetchone()
    fp_total = row["total"]
    fp_avoided = row["avoided"] or 0
    fp_bait = f"{fp_avoided}/{fp_total}" if fp_total > 0 else "--"

    # Dead code
    row = conn.execute(
        """SELECT SUM(CASE WHEN status IN ('matched','partial') THEN 1 ELSE 0 END) as found, COUNT(*) as total
           FROM comparison_items WHERE comparison_id = ? AND answer_category = 'dead-code' AND expected_detection LIKE 'YES%'""",
        (comparison_id,),
    ).fetchone()
    dead_total = row["total"]
    dead_found = row["found"] or 0
    dead_code = f"{dead_found}/{dead_total}" if dead_total > 0 else "--"

    # Trace completeness
    row = conn.execute(
        """SELECT COUNT(*) as total,
                  SUM(CASE WHEN vulnerability_trace IS NOT NULL AND vulnerability_trace != 'null' AND vulnerability_trace != '' THEN 1 ELSE 0 END) as has_trace
           FROM scan_findings WHERE run_id = ? AND vulnerability_type IN ('sqli','nosqli','xss','ssti','ssrf','xxe','path_traversal','deserialization','command_injection','prompt_injection','code_injection','file_upload')""",
        (run_id,),
    ).fetchone()
    trace_total, trace_has = row["total"], row["has_trace"]
    traces = f"{trace_has / trace_total * 100:.1f}%" if trace_total > 0 else "--"

    return {
        "sev_acc": sev_acc,
        "fp_bait": fp_bait,
        "dead_code": dead_code,
        "traces": traces,
        "sev_match": sev_match,
        "sev_total": sev_total,
        "fp_avoided": fp_avoided,
        "fp_total": fp_total,
        "dead_found": dead_found,
        "dead_total": dead_total,
        "trace_has": trace_has or 0,
        "trace_total": trace_total,
    }


def _get_per_domain_recall(conn, comparison_id):
    """Get per-domain recall breakdown."""
    rows = conn.execute(
        """SELECT answer_type, COUNT(*) as expected,
                  SUM(CASE WHEN status IN ('matched','partial') THEN 1 ELSE 0 END) as found
           FROM comparison_items WHERE comparison_id = ? AND expected_detection LIKE 'YES%'
           GROUP BY answer_type ORDER BY answer_type""",
        (comparison_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def cmd_dashboard(args):
    conn = init_db(args.db)

    # Get all runs that have comparisons
    runs = conn.execute(
        """SELECT sr.id as run_id, sr.repo_path, sr.scan_type, sr.model, sr.scanned_at,
                  sr.total_findings, sr.input_tokens, sr.output_tokens,
                  c.id as comparison_id, c.total_expected, c.true_positives,
                  c.precision_score, c.recall_score
           FROM scan_runs sr
           JOIN comparisons c ON c.run_id = sr.id
           ORDER BY sr.repo_path, sr.scanned_at DESC"""
    ).fetchall()

    if not runs:
        print("No runs with comparisons found.", file=sys.stderr)
        sys.exit(0)

    runs = [dict(r) for r in runs]

    # Filter by repo if specified
    if args.repo:
        repo_filter = normalize_repo(args.repo)
        runs = [r for r in runs if normalize_repo(r["repo_path"]) == repo_filter]
        if not runs:
            print(f"No runs found for repo '{args.repo}'.", file=sys.stderr)
            sys.exit(0)

    # Compute metrics for each run
    for r in runs:
        r["repo"] = normalize_repo(r["repo_path"])
        r["metrics"] = _compute_dashboard_metrics(conn, r["run_id"], r["comparison_id"])

    if args.format == "json":
        output = []
        for r in runs:
            domain_recall = _get_per_domain_recall(conn, r["comparison_id"])
            output.append(
                {
                    "run_id": r["run_id"],
                    "repo": r["repo"],
                    "date": r["scanned_at"][:10] if r["scanned_at"] else None,
                    "scan_type": r["scan_type"],
                    "model": r["model"],
                    "total_findings": r["total_findings"],
                    "true_positives": r["true_positives"],
                    "total_expected": r["total_expected"],
                    "recall": r["recall_score"],
                    "precision": r["precision_score"],
                    "severity_accuracy": r["metrics"]["sev_acc"],
                    "fp_bait": r["metrics"]["fp_bait"],
                    "dead_code": r["metrics"]["dead_code"],
                    "traces": r["metrics"]["traces"],
                    "input_tokens": r["input_tokens"],
                    "output_tokens": r["output_tokens"],
                    "domain_recall": domain_recall,
                    "sev_match": r["metrics"]["sev_match"],
                    "sev_total": r["metrics"]["sev_total"],
                    "fp_avoided": r["metrics"]["fp_avoided"],
                    "fp_total": r["metrics"]["fp_total"],
                    "dead_found": r["metrics"]["dead_found"],
                    "dead_total": r["metrics"]["dead_total"],
                    "trace_has": r["metrics"]["trace_has"],
                    "trace_total": r["metrics"]["trace_total"],
                }
            )
        print(json.dumps(output, indent=2))
        conn.close()
        return

    # Group by repo
    repos = {}
    for r in runs:
        repos.setdefault(r["repo"], []).append(r)

    lines = ["## Benchmark Dashboard", ""]

    for repo, repo_runs in repos.items():
        total_expected = repo_runs[0]["total_expected"] if repo_runs else "?"
        lines.append(f"### {repo} ({total_expected} expected)")
        lines.append("")
        lines.append(
            "| Run | Date       | Variant      | Model    | Findings | TP | Recall | Prec  | SevAcc | FPBait | Dead  | Traces | InTok   | OutTok |"
        )
        lines.append(
            "|-----|------------|--------------|----------|----------|----|--------|-------|--------|--------|-------|--------|---------|--------|"
        )

        for r in repo_runs:
            date = r["scanned_at"][:10] if r["scanned_at"] else "--"
            recall = f"{r['recall_score'] * 100:.1f}%" if r["recall_score"] is not None else "--"
            prec = (
                f"{r['precision_score'] * 100:.1f}%" if r["precision_score"] is not None else "--"
            )
            m = r["metrics"]
            lines.append(
                f"| {r['run_id']:>3} | {date} | {r['scan_type']:<12} | {_short_model(r['model']):<8} "
                f"| {r['total_findings']:>8} | {r['true_positives']:>2} | {recall:>6} | {prec:>5} "
                f"| {m['sev_acc']:>6} | {m['fp_bait']:>6} | {m['dead_code']:>5} | {m['traces']:>6} "
                f"| {_fmt_tokens(r['input_tokens']):>7} | {_fmt_tokens(r['output_tokens']):>6} |"
            )

        # Per-domain recall for most recent run
        most_recent = repo_runs[0]
        domain_recall = _get_per_domain_recall(conn, most_recent["comparison_id"])
        if domain_recall:
            lines.append("")
            lines.append(f"#### Per-Domain Recall (Run {most_recent['run_id']})")
            lines.append("| Domain         | Expected | Found | Recall |")
            lines.append("|----------------|----------|-------|--------|")
            for dr in domain_recall:
                found = dr["found"] or 0
                dr_recall = f"{found / dr['expected'] * 100:.1f}%" if dr["expected"] > 0 else "--"
                lines.append(
                    f"| {(dr['answer_type'] or 'unknown'):<14} | {dr['expected']:>8} | {found:>5} | {dr_recall:>6} |"
                )

        lines.append("")

    print("\n".join(lines))
    conn.close()


def _match_findings_across_runs(findings_a, findings_b):
    """Match findings between two runs using file + type + line proximity.

    Returns (common, only_a, only_b) where common contains (fa, fb) tuples.
    """
    matched_b_ids = set()
    common = []
    only_a = []

    for fa in findings_a:
        best = None
        for fb in findings_b:
            if fb["id"] in matched_b_ids:
                continue
            fa_file = (fa.get("file_path") or "").strip("/")
            fb_file = (fb.get("file_path") or "").strip("/")
            fa_type = (fa.get("vulnerability_type") or "").lower()
            fb_type = (fb.get("vulnerability_type") or "").lower()
            fa_line = fa.get("line_start") or 0
            fb_line = fb.get("line_start") or 0

            file_match = fa_file == fb_file
            type_match = fa_type == fb_type
            line_close = abs(fa_line - fb_line) <= LINE_TOLERANCE

            if file_match and type_match and line_close:
                best = fb
                break
            elif file_match and type_match and best is None:
                best = fb

        if best:
            matched_b_ids.add(best["id"])
            common.append((fa, best))
        else:
            only_a.append(fa)

    only_b = [fb for fb in findings_b if fb["id"] not in matched_b_ids]
    return common, only_a, only_b


def cmd_compare_fp_impact(args):
    """Compare FP agent impact by analyzing findings from with-FP and without-FP runs."""
    conn = init_db(args.db)

    # Validate both runs exist
    with_fp_meta = conn.execute(
        "SELECT * FROM scan_runs WHERE id = ?", (args.with_fp_run_id,)
    ).fetchone()
    without_fp_meta = conn.execute(
        "SELECT * FROM scan_runs WHERE id = ?", (args.without_fp_run_id,)
    ).fetchone()

    if not with_fp_meta:
        print(f"ERROR: No run found with id={args.with_fp_run_id}", file=sys.stderr)
        sys.exit(1)
    if not without_fp_meta:
        print(f"ERROR: No run found with id={args.without_fp_run_id}", file=sys.stderr)
        sys.exit(1)

    # Check both runs have been compared against the answer sheet
    comp_with = conn.execute(
        "SELECT * FROM comparisons WHERE run_id = ? AND answer_sheet_path IS NOT NULL ORDER BY id DESC LIMIT 1",
        (args.with_fp_run_id,),
    ).fetchone()
    comp_without = conn.execute(
        "SELECT * FROM comparisons WHERE run_id = ? AND answer_sheet_path IS NOT NULL ORDER BY id DESC LIMIT 1",
        (args.without_fp_run_id,),
    ).fetchone()

    if not comp_with:
        print(
            f"ERROR: Run {args.with_fp_run_id} has not been compared against an answer sheet. "
            f"Run 'compare --run-id {args.with_fp_run_id} --answer-sheet <path>' first.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not comp_without:
        print(
            f"ERROR: Run {args.without_fp_run_id} has not been compared against an answer sheet. "
            f"Run 'compare --run-id {args.without_fp_run_id} --answer-sheet <path>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    comp_with = dict(comp_with)
    comp_without = dict(comp_without)

    # Load findings for both runs (non-FP only)
    findings_with = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM scan_findings WHERE run_id = ? AND is_false_positive = 0",
            (args.with_fp_run_id,),
        ).fetchall()
    ]
    findings_without = [
        dict(r)
        for r in conn.execute(
            "SELECT * FROM scan_findings WHERE run_id = ? AND is_false_positive = 0",
            (args.without_fp_run_id,),
        ).fetchall()
    ]

    # Match findings between runs
    common, only_with, only_without = _match_findings_across_runs(findings_with, findings_without)

    # "Removed" findings = in nofp but not in withfp (FP agent killed them)
    removed = only_without

    # Load answer sheet entries to classify removals
    answer_sheet_path = args.answer_sheet
    entries = parse_answer_sheet(answer_sheet_path)
    yes_entries = [e for e in entries if e.get("expected_detection", "YES").upper() == "YES"]

    # Check each removed finding against the answer sheet
    correct_removals = 0
    incorrect_removals = []
    for rf in removed:
        rf_as_list = [rf]
        matched_entry = None
        for entry in yes_entries:
            match, quality = find_match(entry, rf_as_list)
            if match and quality in ("exact", "partial"):
                matched_entry = entry
                break
        if matched_entry:
            # FP agent removed a true positive -- bad
            incorrect_removals.append(
                {
                    "entry_id": matched_entry.get("id"),
                    "file": rf.get("file_path"),
                    "type": rf.get("vulnerability_type"),
                    "severity": rf.get("severity"),
                    "title": rf.get("title"),
                    "line": rf.get("line_start"),
                }
            )
        else:
            correct_removals += 1

    fp_removal_count = len(removed)
    kill_accuracy = (
        correct_removals / fp_removal_count * 100 if fp_removal_count > 0 else 100.0
    )

    # Recall/precision deltas
    recall_with = comp_with["recall_score"] or 0.0
    recall_without = comp_without["recall_score"] or 0.0
    precision_with = comp_with["precision_score"] or 0.0
    precision_without = comp_without["precision_score"] or 0.0
    recall_delta = recall_with - recall_without
    precision_delta = precision_with - precision_without

    # Severity drift: common findings with different severity
    severity_drifts = []
    for fa, fb in common:
        sev_a = (fa.get("severity") or "").upper()
        sev_b = (fb.get("severity") or "").upper()
        if sev_a != sev_b:
            # Check which matches answer sheet better
            fa_as_list = [fa]
            fb_as_list = [fb]
            answer_sev = None
            for entry in yes_entries:
                match_a, q_a = find_match(entry, fa_as_list)
                if match_a and q_a in ("exact", "partial"):
                    answer_sev = (entry.get("expected_severity") or "").upper()
                    break
            verdict = "unknown"
            if answer_sev:
                if sev_a == answer_sev:
                    verdict = "with-fp-correct"
                elif sev_b == answer_sev:
                    verdict = "without-fp-correct"
                else:
                    verdict = "both-wrong"
            severity_drifts.append(
                {
                    "file": fa.get("file_path"),
                    "type": fa.get("vulnerability_type"),
                    "severity_with_fp": sev_a,
                    "severity_without_fp": sev_b,
                    "answer_severity": answer_sev,
                    "verdict": verdict,
                }
            )

    # FP bait resistance from existing comparisons
    fp_bait_with = "--"
    fp_bait_without = "--"
    row = conn.execute(
        """SELECT SUM(CASE WHEN status='correctly_not_found' THEN 1 ELSE 0 END) as avoided,
                  COUNT(*) as total
           FROM comparison_items WHERE comparison_id = ? AND answer_category = 'false-positive-bait'""",
        (comp_with["id"],),
    ).fetchone()
    if row["total"] > 0:
        fp_bait_with = f"{row['avoided'] or 0}/{row['total']}"
    row = conn.execute(
        """SELECT SUM(CASE WHEN status='correctly_not_found' THEN 1 ELSE 0 END) as avoided,
                  COUNT(*) as total
           FROM comparison_items WHERE comparison_id = ? AND answer_category = 'false-positive-bait'""",
        (comp_without["id"],),
    ).fetchone()
    if row["total"] > 0:
        fp_bait_without = f"{row['avoided'] or 0}/{row['total']}"

    # Per-domain FP rate
    domain_counts_with = {}
    for f in findings_with:
        t = (f.get("vulnerability_type") or "unknown").lower()
        domain_counts_with[t] = domain_counts_with.get(t, 0) + 1
    domain_counts_without = {}
    for f in findings_without:
        t = (f.get("vulnerability_type") or "unknown").lower()
        domain_counts_without[t] = domain_counts_without.get(t, 0) + 1

    all_domains = sorted(set(domain_counts_with.keys()) | set(domain_counts_without.keys()))
    per_domain = []
    for d in all_domains:
        count_with = domain_counts_with.get(d, 0)
        count_without = domain_counts_without.get(d, 0)
        per_domain.append(
            {
                "domain": d,
                "count_with_fp": count_with,
                "count_without_fp": count_without,
                "removals": count_without - count_with,
            }
        )

    # Build markdown summary
    md_lines = [
        "## FP Agent Impact Analysis",
        "",
        f"**With-FP Run**: #{args.with_fp_run_id} ({dict(with_fp_meta).get('scan_type', '--')})",
        f"**Without-FP Run**: #{args.without_fp_run_id} ({dict(without_fp_meta).get('scan_type', '--')})",
        "",
        "### Overall Metrics",
        "",
        "| Metric | Value |",
        "|--------|-------|",
        f"| Findings (with FP) | {len(findings_with)} |",
        f"| Findings (without FP) | {len(findings_without)} |",
        f"| FP Removals | {fp_removal_count} |",
        f"| FP Kill Accuracy | {kill_accuracy:.1f}% |",
        f"| Incorrectly Removed TPs | {len(incorrect_removals)} |",
        f"| Recall (with FP) | {recall_with * 100:.1f}% |",
        f"| Recall (without FP) | {recall_without * 100:.1f}% |",
        f"| Recall Delta | {recall_delta * 100:+.1f}pp |",
        f"| Precision (with FP) | {precision_with * 100:.1f}% |",
        f"| Precision (without FP) | {precision_without * 100:.1f}% |",
        f"| Precision Delta | {precision_delta * 100:+.1f}pp |",
        f"| FP Bait (with FP) | {fp_bait_with} |",
        f"| FP Bait (without FP) | {fp_bait_without} |",
        "",
    ]

    if incorrect_removals:
        md_lines.extend(
            [
                "### Incorrectly Removed True Positives",
                "",
                "| Entry | Type | File | Severity |",
                "|-------|------|------|----------|",
            ]
        )
        for ir in incorrect_removals:
            md_lines.append(
                f"| {ir['entry_id']} | {ir['type']} | {ir['file']} | {ir['severity']} |"
            )
        md_lines.append("")

    if severity_drifts:
        md_lines.extend(
            [
                "### Severity Drift",
                "",
                "| File | Type | With FP | Without FP | Answer | Verdict |",
                "|------|------|---------|------------|--------|---------|",
            ]
        )
        for sd in severity_drifts:
            md_lines.append(
                f"| {sd['file']} | {sd['type']} | {sd['severity_with_fp']} "
                f"| {sd['severity_without_fp']} | {sd['answer_severity'] or '--'} "
                f"| {sd['verdict']} |"
            )
        md_lines.append("")

    md_lines.extend(
        [
            "### Per-Domain FP Rate",
            "",
            "| Domain | With FP | Without FP | Removals |",
            "|--------|---------|------------|----------|",
        ]
    )
    for pd in per_domain:
        md_lines.append(
            f"| {pd['domain']} | {pd['count_with_fp']} | {pd['count_without_fp']} | {pd['removals']} |"
        )

    result = {
        "with_fp_run_id": args.with_fp_run_id,
        "without_fp_run_id": args.without_fp_run_id,
        "findings_with_fp": len(findings_with),
        "findings_without_fp": len(findings_without),
        "fp_removal_count": fp_removal_count,
        "fp_kill_accuracy": round(kill_accuracy, 2),
        "incorrectly_removed_tps": len(incorrect_removals),
        "incorrectly_removed_details": incorrect_removals,
        "recall_with_fp": round(recall_with, 4),
        "recall_without_fp": round(recall_without, 4),
        "recall_delta": round(recall_delta, 4),
        "precision_with_fp": round(precision_with, 4),
        "precision_without_fp": round(precision_without, 4),
        "precision_delta": round(precision_delta, 4),
        "severity_drifts": severity_drifts,
        "fp_bait_with_fp": fp_bait_with,
        "fp_bait_without_fp": fp_bait_without,
        "per_domain": per_domain,
        "markdown_summary": "\n".join(md_lines),
    }

    print(json.dumps(result, indent=2))
    conn.close()


def cmd_trends(args):
    conn = init_db(args.db)

    if not args.repo:
        print("ERROR: --repo is required for trends", file=sys.stderr)
        sys.exit(1)

    repo_filter = normalize_repo(args.repo)

    runs = conn.execute(
        """SELECT sr.id as run_id, sr.repo_path, sr.scan_type, sr.model, sr.scanned_at,
                  c.recall_score, c.precision_score
           FROM scan_runs sr
           JOIN comparisons c ON c.run_id = sr.id
           ORDER BY sr.scanned_at ASC"""
    ).fetchall()

    runs = [dict(r) for r in runs if normalize_repo(r["repo_path"]) == repo_filter]

    if not runs:
        print(f"No runs with comparisons found for repo '{args.repo}'.", file=sys.stderr)
        sys.exit(0)

    # Compute deltas
    for i, r in enumerate(runs):
        if i == 0:
            r["recall_delta"] = None
            r["precision_delta"] = None
        else:
            prev = runs[i - 1]
            if r["recall_score"] is not None and prev["recall_score"] is not None:
                r["recall_delta"] = (r["recall_score"] - prev["recall_score"]) * 100
            else:
                r["recall_delta"] = None
            if r["precision_score"] is not None and prev["precision_score"] is not None:
                r["precision_delta"] = (r["precision_score"] - prev["precision_score"]) * 100
            else:
                r["precision_delta"] = None

    if args.format == "json":
        output = []
        for r in runs:
            output.append(
                {
                    "run_id": r["run_id"],
                    "repo": repo_filter,
                    "date": r["scanned_at"][:10] if r["scanned_at"] else None,
                    "scan_type": r["scan_type"],
                    "model": r["model"],
                    "recall": r["recall_score"],
                    "precision": r["precision_score"],
                    "recall_delta": round(r["recall_delta"], 1)
                    if r["recall_delta"] is not None
                    else None,
                    "precision_delta": round(r["precision_delta"], 1)
                    if r["precision_delta"] is not None
                    else None,
                }
            )
        print(json.dumps(output, indent=2))
        conn.close()
        return

    lines = [f"## Trends: {repo_filter}", ""]
    lines.append(
        "| Run | Date       | Variant      | Model    | Recall  | Delta   | Precision | Delta   |"
    )
    lines.append(
        "|-----|------------|--------------|----------|---------|---------|-----------|---------|"
    )

    for r in runs:
        date = r["scanned_at"][:10] if r["scanned_at"] else "--"
        recall = f"{r['recall_score'] * 100:.1f}%" if r["recall_score"] is not None else "--"
        prec = f"{r['precision_score'] * 100:.1f}%" if r["precision_score"] is not None else "--"

        if r["recall_delta"] is not None:
            rd = r["recall_delta"]
            recall_delta = f"{'+' if rd >= 0 else ''}{rd:.1f}pp"
        else:
            recall_delta = "--"

        if r["precision_delta"] is not None:
            pd = r["precision_delta"]
            prec_delta = f"{'+' if pd >= 0 else ''}{pd:.1f}pp"
        else:
            prec_delta = "--"

        lines.append(
            f"| {r['run_id']:>3} | {date} | {r['scan_type']:<12} | {_short_model(r['model']):<8} "
            f"| {recall:>7} | {recall_delta:>7} | {prec:>9} | {prec_delta:>7} |"
        )

    print("\n".join(lines))
    conn.close()


def main():
    parser = argparse.ArgumentParser(description="Store and compare security scan findings")
    sub = parser.add_subparsers(dest="command", required=True)

    p_store = sub.add_parser("store", help="Store scan findings")
    p_store.add_argument("--db", default="railguard-benchmarks.db", help="SQLite database path")
    p_store.add_argument("--repo", required=True, help="Repository path that was scanned")
    p_store.add_argument("--findings", required=True, help="Path to findings JSON file")
    p_store.add_argument(
        "--scan-type", default="skill", help="Scan type label (skill, orchestrated, production)"
    )
    p_store.add_argument(
        "--model", help="Model used for this scan (e.g., claude-sonnet-4-5, claude-opus-4-5)"
    )
    p_store.add_argument("--notes", help="Optional notes about this scan run")
    p_store.add_argument("--duration-ms", type=int, help="Scan duration in milliseconds")
    p_store.add_argument("--input-tokens", type=int, help="Total input tokens used")
    p_store.add_argument("--output-tokens", type=int, help="Total output tokens used")
    p_store.add_argument("--cost-usd", type=float, help="Total cost in USD")
    p_store.add_argument("--files-analyzed", type=int, help="Number of files analyzed")
    p_store.add_argument("--flows-traced", type=int, help="Number of data flows traced")
    p_store.add_argument("--subagent-count", type=int, help="Number of subagents used")

    p_compare = sub.add_parser("compare", help="Compare scan against answer sheet")
    p_compare.add_argument("--db", default="railguard-benchmarks.db", help="SQLite database path")
    p_compare.add_argument("--run-id", type=int, required=True, help="Scan run ID to compare")
    p_compare.add_argument("--answer-sheet", required=True, help="Path to answer sheet markdown")

    p_compare_runs = sub.add_parser("compare-runs", help="Compare two scan runs")
    p_compare_runs.add_argument(
        "--db", default="railguard-benchmarks.db", help="SQLite database path"
    )
    p_compare_runs.add_argument("--run-a", type=int, required=True, help="First scan run ID")
    p_compare_runs.add_argument("--run-b", type=int, required=True, help="Second scan run ID")

    p_list = sub.add_parser("list", help="List all stored scan runs")
    p_list.add_argument("--db", default="railguard-benchmarks.db", help="SQLite database path")

    p_dashboard = sub.add_parser("dashboard", help="Show benchmark dashboard with metrics")
    p_dashboard.add_argument("--db", default="railguard-benchmarks.db", help="SQLite database path")
    p_dashboard.add_argument("--repo", help="Filter to a specific repository")
    p_dashboard.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )

    p_trends = sub.add_parser("trends", help="Show recall/precision trends over time")
    p_trends.add_argument("--db", default="railguard-benchmarks.db", help="SQLite database path")
    p_trends.add_argument("--repo", required=True, help="Repository to show trends for")
    p_trends.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )

    p_fp_impact = sub.add_parser(
        "compare-fp-impact", help="Compare FP agent impact between with-FP and without-FP runs"
    )
    p_fp_impact.add_argument(
        "--db", default="railguard-benchmarks.db", help="SQLite database path"
    )
    p_fp_impact.add_argument(
        "--with-fp-run-id", type=int, required=True, help="Run ID from scan WITH FP validation"
    )
    p_fp_impact.add_argument(
        "--without-fp-run-id",
        type=int,
        required=True,
        help="Run ID from scan WITHOUT FP validation",
    )
    p_fp_impact.add_argument(
        "--answer-sheet", required=True, help="Path to answer sheet markdown"
    )

    args = parser.parse_args()

    if args.command == "store":
        cmd_store(args)
    elif args.command == "compare":
        cmd_compare(args)
    elif args.command == "compare-runs":
        cmd_compare_runs(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "trends":
        cmd_trends(args)
    elif args.command == "compare-fp-impact":
        cmd_compare_fp_impact(args)


if __name__ == "__main__":
    main()
