#!/usr/bin/env python3
"""merge-findings.py — Merge, normalize, and batch Phase 3/4 scan findings.

Replaces all inline Python snippets in the orchestrator SKILL.md with a single
testable script. Handles format normalization (bare arrays vs wrapped objects)
to prevent the cascade failure when agents write non-array output.

Usage:
    python3 merge-findings.py --scan-id <ID> verify-p3
    python3 merge-findings.py --scan-id <ID> merge-p3 [--batch-size 25]
    python3 merge-findings.py --scan-id <ID> merge-p4
    python3 merge-findings.py --scan-id <ID> read-validated
"""

import argparse
import glob
import json
import sys
from pathlib import Path


def normalize_findings(data, source_path: str) -> list:
    """Extract a findings list from whatever format the agent wrote."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if "findings" in data:
            print(f"WARN: {source_path} wrote object with .findings key, extracting array", file=sys.stderr)
            findings = data["findings"]
            if isinstance(findings, list):
                return findings
        nested = []
        for val in data.values():
            if isinstance(val, list):
                nested.extend(val)
        if nested:
            print(f"WARN: {source_path} wrote unexpected object, extracted {len(nested)} items from nested lists", file=sys.stderr)
            return nested
    print(f"WARN: {source_path} has unrecognized format ({type(data).__name__}), skipping", file=sys.stderr)
    return []


def dedup_findings(findings: list) -> list:
    """First-pass deduplication: same file + type + line within +/-2."""
    seen = set()
    deduped = []
    for f in findings:
        if not isinstance(f, dict):
            print(f"WARN: skipping non-dict finding: {str(f)[:80]}", file=sys.stderr)
            continue
        key_file = f.get("file", "")
        key_type = f.get("type", "")
        key_line = f.get("line_start", 0)
        is_dup = False
        for offset in range(-2, 3):
            if (key_file, key_type, key_line + offset) in seen:
                is_dup = True
                break
        if not is_dup:
            seen.add((key_file, key_type, key_line))
            deduped.append(f)
    removed = len(findings) - len(deduped)
    if removed:
        print(f"Dedup: removed {removed} duplicates, {len(deduped)} remaining", file=sys.stderr)
    return deduped


def cmd_verify_p3(scan_id: str):
    """Verify Phase 3 output files exist and contain valid JSON."""
    pattern = f"/tmp/rgs-{scan_id}-*.json"
    files = sorted(glob.glob(pattern))
    files = [f for f in files if "p4-" not in f and "validated" not in f]

    if not files:
        print(f"ERROR: No Phase 3 output files found matching {pattern}", file=sys.stderr)
        sys.exit(1)

    total = 0
    errors = 0
    for path in files:
        try:
            with open(path) as fh:
                data = json.load(fh)
            findings = normalize_findings(data, path)
            count = len(findings)
            total += count
            slug = Path(path).stem.replace(f"rgs-{scan_id}-", "")
            print(f"  {slug}: {count} findings")
        except Exception as e:
            print(f"  ERROR: {path}: {e}", file=sys.stderr)
            errors += 1

    print(f"\nTotal: {total} findings across {len(files)} files, {errors} errors")
    if errors:
        sys.exit(1)


def cmd_merge_p3(scan_id: str, batch_size: int):
    """Merge Phase 3 output files, dedup, and split into FP validation batches."""
    pattern = f"/tmp/rgs-{scan_id}-*.json"
    files = sorted(glob.glob(pattern))
    files = [f for f in files if "p4-" not in f and "validated" not in f]

    if not files:
        print(f"ERROR: No Phase 3 output files found matching {pattern}", file=sys.stderr)
        sys.exit(1)

    merged = []
    for path in files:
        try:
            with open(path) as fh:
                data = json.load(fh)
            findings = normalize_findings(data, path)
            merged.extend(findings)
            print(f"Loaded {len(findings)} from {path}", file=sys.stderr)
        except Exception as e:
            print(f"Failed to load {path}: {e}", file=sys.stderr)

    print(f"Total merged: {len(merged)}", file=sys.stderr)

    deduped = dedup_findings(merged)

    for i in range(0, len(deduped), batch_size):
        batch = deduped[i : i + batch_size]
        batch_num = i // batch_size + 1
        batch_path = f"/tmp/rgs-{scan_id}-p4-input-{batch_num}.json"
        with open(batch_path, "w") as fh:
            json.dump(batch, fh, indent=2)
        print(f"Wrote batch {batch_num}: {len(batch)} findings to {batch_path}", file=sys.stderr)

    batch_count = (len(deduped) + batch_size - 1) // batch_size if deduped else 0
    print(json.dumps({
        "total_merged": len(merged),
        "after_dedup": len(deduped),
        "batches": batch_count,
        "batch_size": batch_size,
    }))


def cmd_merge_p4(scan_id: str):
    """Merge FP validation output files into a single validated findings file."""
    pattern = f"/tmp/rgs-{scan_id}-p4-output-*.json"
    files = sorted(glob.glob(pattern))

    if not files:
        print(f"ERROR: No Phase 4 output files found matching {pattern}", file=sys.stderr)
        sys.exit(1)

    merged = []
    for path in files:
        try:
            with open(path) as fh:
                data = json.load(fh)
            findings = normalize_findings(data, path)
            merged.extend(findings)
            print(f"Loaded {len(findings)} from {path}", file=sys.stderr)
        except Exception as e:
            print(f"Failed to load {path}: {e}", file=sys.stderr)

    output_path = f"/tmp/rgs-{scan_id}-validated.json"
    with open(output_path, "w") as fh:
        json.dump(merged, fh, indent=2)

    print(f"{len(merged)} validated findings written to {output_path}")


def cmd_read_validated(scan_id: str):
    """Read and print the validated findings JSON to stdout."""
    path = f"/tmp/rgs-{scan_id}-validated.json"
    try:
        with open(path) as fh:
            data = json.load(fh)
        print(json.dumps(data, indent=2))
    except FileNotFoundError:
        print(f"ERROR: Validated findings file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"ERROR: Invalid JSON in {path}: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Merge and batch scan findings")
    parser.add_argument("--scan-id", required=True, help="Scan ID (timestamp) for file namespace")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("verify-p3", help="Verify Phase 3 output files")

    p3 = sub.add_parser("merge-p3", help="Merge Phase 3 findings into FP batches")
    p3.add_argument("--batch-size", type=int, default=25, help="Max findings per batch")

    sub.add_parser("merge-p4", help="Merge Phase 4 output into validated file")
    sub.add_parser("read-validated", help="Print validated findings to stdout")

    args = parser.parse_args()

    if args.command == "verify-p3":
        cmd_verify_p3(args.scan_id)
    elif args.command == "merge-p3":
        cmd_merge_p3(args.scan_id, args.batch_size)
    elif args.command == "merge-p4":
        cmd_merge_p4(args.scan_id)
    elif args.command == "read-validated":
        cmd_read_validated(args.scan_id)


if __name__ == "__main__":
    main()
