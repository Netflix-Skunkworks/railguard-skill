"""Tests for store-and-compare.py benchmark tool."""

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = str(Path(__file__).parent / "store-and-compare.py")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ANSWER_SHEET_TEMPLATE = """\
# Test Answer Sheet

### PV-001: SQL Injection in login

| Field | Value |
|-------|-------|
| **Agent** | sqli |
| **Vulnerability Type** | sqli |
| **Category** | active |
| **File** | `app/routes/auth.py` |
| **Line Range** | 42 |
| **Expected Severity** | CRITICAL |
| **Expected Detection** | YES |

### PV-002: XSS in search

| Field | Value |
|-------|-------|
| **Agent** | xss |
| **Vulnerability Type** | xss |
| **Category** | active |
| **File** | `app/routes/search.py` |
| **Line Range** | 18 |
| **Expected Severity** | HIGH |
| **Expected Detection** | YES |

### PV-003: Hardcoded secret

| Field | Value |
|-------|-------|
| **Agent** | secrets |
| **Vulnerability Type** | hardcoded_secret |
| **Category** | active |
| **File** | `app/config.py` |
| **Line Range** | 5 |
| **Expected Severity** | HIGH |
| **Expected Detection** | YES |

### PV-004: Dead code SSRF

| Field | Value |
|-------|-------|
| **Agent** | ssrf |
| **Vulnerability Type** | ssrf |
| **Category** | dead-code |
| **File** | `app/utils/old.py` |
| **Line Range** | 100 |
| **Expected Severity** | HIGH |
| **Expected Detection** | YES (WITH DEAD-CODE NOTE) |

### PV-005: FP bait logging

| Field | Value |
|-------|-------|
| **Agent** | sqli |
| **Vulnerability Type** | sqli |
| **Category** | false-positive-bait |
| **File** | `app/routes/logs.py` |
| **Line Range** | 30 |
| **Expected Severity** | MEDIUM |
| **Expected Detection** | NO |
"""


def make_findings(include_trace=True):
    """Create test findings that match most of the answer sheet."""
    return [
        {
            "severity": "CRITICAL",
            "type": "sqli",
            "title": "SQL Injection in login handler",
            "file": "app/routes/auth.py",
            "line_start": 42,
            "line_end": 50,
            "vulnerability_trace": {"source": "request.form", "sink": "cursor.execute"}
            if include_trace
            else None,
        },
        {
            "severity": "HIGH",
            "type": "xss",
            "title": "Reflected XSS in search results",
            "file": "app/routes/search.py",
            "line_start": 18,
            "line_end": 25,
            "vulnerability_trace": {"source": "request.args", "sink": "render_template"}
            if include_trace
            else None,
        },
        {
            "severity": "MEDIUM",  # severity mismatch with answer (HIGH)
            "type": "hardcoded_secret",
            "title": "API key in config",
            "file": "app/config.py",
            "line_start": 5,
            "line_end": 5,
        },
        {
            "severity": "HIGH",
            "type": "ssrf",
            "title": "SSRF in old utility",
            "file": "app/utils/old.py",
            "line_start": 100,
            "line_end": 110,
        },
        {
            "severity": "LOW",
            "type": "information_disclosure",
            "title": "Extra finding not in answer sheet",
            "file": "app/routes/api.py",
            "line_start": 200,
            "line_end": 205,
        },
    ]


def run_script(*args, check=True):
    """Run store-and-compare.py with given args, return stdout."""
    result = subprocess.run(
        [sys.executable, SCRIPT, *args],
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Script failed: {result.stderr}")
    return result


@pytest.fixture
def tmp_db(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def answer_sheet(tmp_path):
    path = tmp_path / "answer-sheet.md"
    path.write_text(ANSWER_SHEET_TEMPLATE)
    return str(path)


@pytest.fixture
def populated_db(tmp_path, answer_sheet):
    """Create a DB with 2 runs and comparisons for dashboard/trends tests."""
    db = str(tmp_path / "populated.db")
    findings_file = str(tmp_path / "findings.json")

    # Run 1: orchestrated scan
    findings1 = make_findings(include_trace=False)
    Path(findings_file).write_text(json.dumps(findings1))
    run_script(
        "store",
        "--db",
        db,
        "--repo",
        "repos/pixel-vault",
        "--findings",
        findings_file,
        "--scan-type",
        "orchestrated",
        "--model",
        "claude-opus-4-5",
    )
    run_script("compare", "--db", db, "--run-id", "1", "--answer-sheet", answer_sheet)

    # Run 2: superagent scan with tokens
    findings2 = make_findings(include_trace=True)
    Path(findings_file).write_text(json.dumps(findings2))
    run_script(
        "store",
        "--db",
        db,
        "--repo",
        "repos/pixel-vault",
        "--findings",
        findings_file,
        "--scan-type",
        "superagent",
        "--model",
        "claude-opus-4-6",
        "--input-tokens",
        "125400",
        "--output-tokens",
        "32100",
    )
    run_script("compare", "--db", db, "--run-id", "2", "--answer-sheet", answer_sheet)

    return db


# ---------------------------------------------------------------------------
# Test 1: Migration idempotency
# ---------------------------------------------------------------------------


def test_migration_idempotency(tmp_db):
    """Calling init_db twice should not error; new columns must exist."""
    # Import the module
    sys.path.insert(0, str(Path(SCRIPT).parent))
    import importlib

    sac = importlib.import_module("store-and-compare")

    conn1 = sac.init_db(tmp_db)
    conn1.close()

    # Second call should be idempotent
    conn2 = sac.init_db(tmp_db)

    # Verify new columns exist
    cursor = conn2.execute("PRAGMA table_info(scan_runs)")
    columns = {row["name"] for row in cursor.fetchall()}
    for col_name, _ in sac.MIGRATION_COLUMNS:
        assert col_name in columns, f"Column {col_name} missing after migration"

    conn2.close()


# ---------------------------------------------------------------------------
# Test 2: Store basic
# ---------------------------------------------------------------------------


def test_store_basic(tmp_db, tmp_path):
    findings = make_findings()
    findings_file = str(tmp_path / "findings.json")
    Path(findings_file).write_text(json.dumps(findings))

    result = run_script(
        "store",
        "--db",
        tmp_db,
        "--repo",
        "repos/pixel-vault",
        "--findings",
        findings_file,
        "--scan-type",
        "skill",
        "--model",
        "claude-sonnet-4-5",
    )

    output = json.loads(result.stdout)
    assert output["status"] == "stored"
    assert output["run_id"] == 1
    assert output["findings_count"] == len(findings)


# ---------------------------------------------------------------------------
# Test 3: Store with new flags
# ---------------------------------------------------------------------------


def test_store_with_new_flags(tmp_db, tmp_path):
    findings_file = str(tmp_path / "findings.json")
    Path(findings_file).write_text(json.dumps([]))

    run_script(
        "store",
        "--db",
        tmp_db,
        "--repo",
        "repos/test",
        "--findings",
        findings_file,
        "--duration-ms",
        "45000",
        "--input-tokens",
        "500000",
        "--output-tokens",
        "12000",
        "--cost-usd",
        "3.50",
        "--files-analyzed",
        "42",
        "--flows-traced",
        "87",
        "--subagent-count",
        "15",
    )

    conn = sqlite3.connect(tmp_db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM scan_runs WHERE id = 1").fetchone()
    assert row["duration_ms"] == 45000
    assert row["input_tokens"] == 500000
    assert row["output_tokens"] == 12000
    assert abs(row["cost_usd"] - 3.50) < 0.01
    assert row["files_analyzed"] == 42
    assert row["flows_traced"] == 87
    assert row["subagent_count"] == 15
    conn.close()


# ---------------------------------------------------------------------------
# Test 4: Store backward compat
# ---------------------------------------------------------------------------


def test_store_backward_compat(tmp_db, tmp_path):
    findings_file = str(tmp_path / "findings.json")
    Path(findings_file).write_text(
        json.dumps([{"severity": "LOW", "title": "test", "file": "a.py"}])
    )

    run_script(
        "store",
        "--db",
        tmp_db,
        "--repo",
        "repos/test",
        "--findings",
        findings_file,
    )

    conn = sqlite3.connect(tmp_db)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM scan_runs WHERE id = 1").fetchone()
    assert row["duration_ms"] is None
    assert row["input_tokens"] is None
    assert row["output_tokens"] is None
    assert row["cost_usd"] is None
    assert row["files_analyzed"] is None
    assert row["flows_traced"] is None
    assert row["subagent_count"] is None
    conn.close()


# ---------------------------------------------------------------------------
# Test 5: Compare against answer sheet
# ---------------------------------------------------------------------------


def test_compare_answer_sheet(tmp_db, tmp_path, answer_sheet):
    findings = make_findings()
    findings_file = str(tmp_path / "findings.json")
    Path(findings_file).write_text(json.dumps(findings))

    run_script(
        "store",
        "--db",
        tmp_db,
        "--repo",
        "repos/pixel-vault",
        "--findings",
        findings_file,
    )

    result = run_script("compare", "--db", tmp_db, "--run-id", "1", "--answer-sheet", answer_sheet)
    output = json.loads(result.stdout)

    # 3 active YES entries should match (sqli, xss, hardcoded_secret)
    # 1 dead-code YES entry should match (ssrf)
    # 1 FP bait NO entry should be correctly_not_found
    assert output["summary"]["true_positives"] == 3  # 3 active YES matched
    assert output["summary"]["false_negatives"] == 0
    assert output["summary"]["extra_findings"] == 1  # extra info_disclosure

    # Verify FP bait
    fp_items = [i for i in output["items"] if i["answer_category"] == "false-positive-bait"]
    assert len(fp_items) == 1
    assert fp_items[0]["status"] == "correctly_not_found"


# ---------------------------------------------------------------------------
# Test 6: Dashboard output
# ---------------------------------------------------------------------------


def test_dashboard_output(populated_db):
    result = run_script("dashboard", "--db", populated_db)
    output = result.stdout

    # Should contain header
    assert "Benchmark Dashboard" in output
    # Should be grouped by repo
    assert "pixel-vault" in output
    # Should have both runs
    assert "orchestrated" in output
    assert "superagent" in output
    # Should show SevAcc, FPBait, Dead columns
    assert "SevAcc" in output
    assert "FPBait" in output
    assert "Dead" in output
    assert "Traces" in output
    # Should have per-domain recall section
    assert "Per-Domain Recall" in output
    # Token columns should show formatted values for run 2
    assert "125.4K" in output
    assert "32.1K" in output


# ---------------------------------------------------------------------------
# Test 7: Dashboard JSON format
# ---------------------------------------------------------------------------


def test_dashboard_json(populated_db):
    result = run_script("dashboard", "--db", populated_db, "--format", "json")
    output = json.loads(result.stdout)

    assert isinstance(output, list)
    assert len(output) == 2

    # Check first entry has all expected fields
    entry = output[0]
    assert "run_id" in entry
    assert "repo" in entry
    assert "recall" in entry
    assert "precision" in entry
    assert "severity_accuracy" in entry
    assert "fp_bait" in entry
    assert "dead_code" in entry
    assert "traces" in entry
    assert "domain_recall" in entry
    assert "input_tokens" in entry
    assert "output_tokens" in entry


# ---------------------------------------------------------------------------
# Test 8: Dashboard repo filter
# ---------------------------------------------------------------------------


def test_dashboard_repo_filter(populated_db, tmp_path):
    # Add a run for a different repo
    findings_file = str(tmp_path / "findings2.json")
    Path(findings_file).write_text(
        json.dumps([{"severity": "LOW", "title": "test", "file": "x.py", "type": "xss"}])
    )
    run_script(
        "store", "--db", populated_db, "--repo", "repos/other-repo", "--findings", findings_file
    )

    # Dashboard filtered to pixel-vault should not show other-repo
    result = run_script("dashboard", "--db", populated_db, "--repo", "pixel-vault")
    assert "other-repo" not in result.stdout
    assert "pixel-vault" in result.stdout


# ---------------------------------------------------------------------------
# Test 9: Trends output
# ---------------------------------------------------------------------------


def test_trends_output(populated_db):
    result = run_script("trends", "--db", populated_db, "--repo", "pixel-vault")
    output = result.stdout

    assert "Trends: pixel-vault" in output
    assert "Delta" in output
    # First run should have "--" for delta
    # Second run should have actual delta values
    lines = output.strip().split("\n")
    data_lines = [
        row for row in lines if row.startswith("|") and "Run" not in row and "---" not in row
    ]
    assert len(data_lines) == 2

    # First run should have "--" delta
    assert "--" in data_lines[0].split("|")[6]  # recall delta column


# ---------------------------------------------------------------------------
# Test 10: Trends JSON format
# ---------------------------------------------------------------------------


def test_trends_json(populated_db):
    result = run_script("trends", "--db", populated_db, "--repo", "pixel-vault", "--format", "json")
    output = json.loads(result.stdout)

    assert isinstance(output, list)
    assert len(output) == 2

    # First run has no delta
    assert output[0]["recall_delta"] is None
    assert output[0]["precision_delta"] is None

    # Second run has deltas
    assert output[1]["recall_delta"] is not None or output[1]["recall_delta"] == 0.0
    assert output[1]["precision_delta"] is not None or output[1]["precision_delta"] == 0.0


# ---------------------------------------------------------------------------
# Test 11: Repo normalization
# ---------------------------------------------------------------------------


def test_normalize_repo():
    sys.path.insert(0, str(Path(SCRIPT).parent))
    import importlib

    sac = importlib.import_module("store-and-compare")

    assert sac.normalize_repo("repos/pixel-vault") == "pixel-vault"
    assert (
        sac.normalize_repo("/path/to/repo/repos/my-target-repo") == "pixel-vault"
    )
    assert sac.normalize_repo("repos/pixel-vault/") == "pixel-vault"
    assert sac.normalize_repo("/some/other/path") == "path"
    assert sac.normalize_repo("single-name") == "single-name"


# ---------------------------------------------------------------------------
# Test 12: Token formatting
# ---------------------------------------------------------------------------


def test_fmt_tokens():
    sys.path.insert(0, str(Path(SCRIPT).parent))
    import importlib

    sac = importlib.import_module("store-and-compare")

    assert sac._fmt_tokens(None) == "--"
    assert sac._fmt_tokens(500) == "500"
    assert sac._fmt_tokens(125400) == "125.4K"
    assert sac._fmt_tokens(1200000) == "1.2M"
    assert sac._fmt_tokens(0) == "0"
    assert sac._fmt_tokens(999) == "999"
    assert sac._fmt_tokens(1000) == "1.0K"


# ---------------------------------------------------------------------------
# Test 13: Compare FP impact basic
# ---------------------------------------------------------------------------


def test_compare_fp_impact_basic(tmp_path, answer_sheet):
    """Store two runs (with-FP and without-FP), compare both, run fp-impact."""
    db = str(tmp_path / "fp-impact.db")
    findings_file = str(tmp_path / "findings.json")

    # Run 1: "with FP" -- has 4 findings (FP agent removed 2 from the nofp set)
    findings_with_fp = [
        {
            "severity": "CRITICAL",
            "type": "sqli",
            "title": "SQL Injection in login handler",
            "file": "app/routes/auth.py",
            "line_start": 42,
            "line_end": 50,
        },
        {
            "severity": "HIGH",
            "type": "xss",
            "title": "Reflected XSS in search results",
            "file": "app/routes/search.py",
            "line_start": 18,
            "line_end": 25,
        },
        {
            "severity": "HIGH",
            "type": "hardcoded_secret",
            "title": "API key in config",
            "file": "app/config.py",
            "line_start": 5,
            "line_end": 5,
        },
        {
            "severity": "HIGH",
            "type": "ssrf",
            "title": "SSRF in old utility",
            "file": "app/utils/old.py",
            "line_start": 100,
            "line_end": 110,
        },
    ]
    Path(findings_file).write_text(json.dumps(findings_with_fp))
    run_script(
        "store",
        "--db", db,
        "--repo", "repos/pixel-vault",
        "--findings", findings_file,
        "--scan-type", "orchestrated",
    )
    run_script("compare", "--db", db, "--run-id", "1", "--answer-sheet", answer_sheet)

    # Run 2: "without FP" -- has 6 findings (2 extra that FP agent would have removed)
    findings_without_fp = findings_with_fp + [
        {
            "severity": "MEDIUM",
            "type": "xss",
            "title": "False positive XSS in template",
            "file": "app/templates/base.py",
            "line_start": 10,
            "line_end": 15,
        },
        {
            "severity": "LOW",
            "type": "information_disclosure",
            "title": "Debug info exposure",
            "file": "app/routes/debug.py",
            "line_start": 50,
            "line_end": 55,
        },
    ]
    Path(findings_file).write_text(json.dumps(findings_without_fp))
    run_script(
        "store",
        "--db", db,
        "--repo", "repos/pixel-vault",
        "--findings", findings_file,
        "--scan-type", "nofp-orchestrated",
    )
    run_script("compare", "--db", db, "--run-id", "2", "--answer-sheet", answer_sheet)

    # Run compare-fp-impact
    result = run_script(
        "compare-fp-impact",
        "--db", db,
        "--with-fp-run-id", "1",
        "--without-fp-run-id", "2",
        "--answer-sheet", answer_sheet,
    )
    output = json.loads(result.stdout)

    # Verify output structure
    assert output["with_fp_run_id"] == 1
    assert output["without_fp_run_id"] == 2
    assert output["findings_with_fp"] == 4
    assert output["findings_without_fp"] == 6
    assert output["fp_removal_count"] == 2  # 2 findings in nofp but not in withfp
    assert output["fp_kill_accuracy"] == 100.0  # both removals are correct (not in answer sheet)
    assert output["incorrectly_removed_tps"] == 0
    assert "recall_delta" in output
    assert "precision_delta" in output
    assert "severity_drifts" in output
    assert "per_domain" in output
    assert "markdown_summary" in output
    assert "FP Agent Impact" in output["markdown_summary"]


# ---------------------------------------------------------------------------
# Test 14: Compare FP impact missing comparison
# ---------------------------------------------------------------------------


def test_compare_fp_impact_missing_comparison(tmp_path, answer_sheet):
    """Error when runs haven't been compared against answer sheet first."""
    db = str(tmp_path / "fp-impact-missing.db")
    findings_file = str(tmp_path / "findings.json")

    # Store a run but don't compare it
    Path(findings_file).write_text(
        json.dumps([{"severity": "HIGH", "type": "xss", "title": "test", "file": "a.py"}])
    )
    run_script(
        "store",
        "--db", db,
        "--repo", "repos/test",
        "--findings", findings_file,
    )

    # Store a second run
    run_script(
        "store",
        "--db", db,
        "--repo", "repos/test",
        "--findings", findings_file,
    )

    # Try compare-fp-impact without having compared either run
    result = run_script(
        "compare-fp-impact",
        "--db", db,
        "--with-fp-run-id", "1",
        "--without-fp-run-id", "2",
        "--answer-sheet", answer_sheet,
        check=False,
    )
    assert result.returncode != 0
    assert "has not been compared" in result.stderr
