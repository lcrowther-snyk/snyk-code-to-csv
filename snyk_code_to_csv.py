#!/usr/bin/env python3
"""
snyk_code_to_csv.py

Run `snyk code test` and export the findings to a CSV that includes the full
source-to-sink data flow (with real code snippets) and the remediation advice
("how to fix") for every issue.

The CSV is built from Snyk Code's SARIF output, which is the only format that
carries both the data-flow steps (codeFlows/threadFlows) and the per-rule
remediation guidance (rule.help.markdown).

Usage:
    # Scan a project and write snyk-code-results.csv
    ./snyk_code_to_csv.py /path/to/project

    # Re-use an existing SARIF file instead of scanning
    ./snyk_code_to_csv.py --sarif-input results.sarif --project-root /path/to/project

    # Custom output path and pass extra args through to the Snyk CLI
    ./snyk_code_to_csv.py . -o findings.csv -- --org=my-org --severity-threshold=medium

Snyk CLI exit codes: 0 = no issues, 1 = issues found (both are success here),
2 = scan error.
"""

import argparse
import csv
import json
import os
import subprocess
import sys
import tempfile

# SARIF `level` -> Snyk severity label
LEVEL_TO_SEVERITY = {"error": "High", "warning": "Medium", "note": "Low"}
SEVERITY_ORDER = {"High": 0, "Medium": 1, "Low": 2}

CSV_COLUMNS = [
    "severity",
    "issue_title",
    "rule_id",
    "cwe",
    "priority_score",
    "file",
    "line",
    "message",
    "source",
    "sink",
    "data_flow",
    "remediation",
    "autofixable",
    "fingerprint",
]


def validate_input_path(raw_path):
    """Resolve a user-supplied SARIF path and confine it to the working directory.

    The path is canonicalised (resolving symlinks and ``..``) and then required
    to live inside the current working directory tree. This blocks path
    traversal -- the input cannot escape the project to read arbitrary files
    such as ``../../etc/passwd`` -- and rejects anything that is not a real
    regular file.
    """
    base = os.path.realpath(os.getcwd())
    resolved = os.path.realpath(raw_path)
    try:
        contained = os.path.commonpath([base, resolved]) == base
    except ValueError:  # different drives (Windows) -> not contained
        contained = False
    if not contained:
        raise SystemExit(
            f"SARIF input must be inside the working directory ({base}): {raw_path}"
        )
    if not os.path.isfile(resolved):
        raise SystemExit(f"SARIF input is not a readable file: {raw_path}")
    return resolved


def run_snyk_code(target, extra_args):
    """Run `snyk code test` writing SARIF to a temp file. Returns the SARIF path."""
    tmp = tempfile.NamedTemporaryFile(
        prefix="snyk-code-", suffix=".sarif", delete=False
    )
    tmp.close()
    cmd = ["snyk", "code", "test", target, f"--sarif-file-output={tmp.name}"]
    cmd.extend(extra_args)
    print(f"Running: {' '.join(cmd)}", file=sys.stderr)
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # 0 = clean, 1 = issues found -> both fine. Anything else and no sarif = error.
    if result.returncode not in (0, 1) and not os.path.getsize(tmp.name):
        sys.stderr.write(result.stdout.decode("utf-8", "replace"))
        raise SystemExit(f"snyk code test failed (exit {result.returncode})")
    if not os.path.getsize(tmp.name):
        sys.stderr.write(result.stdout.decode("utf-8", "replace"))
        raise SystemExit("snyk produced no SARIF output (no results or scan error)")
    return tmp.name


class SourceReader:
    """Reads and caches source files so we can attach real code to flow steps."""

    def __init__(self, project_root):
        self.root = project_root
        self.cache = {}

    def _load(self, uri):
        if uri not in self.cache:
            path = os.path.join(self.root, uri)
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    self.cache[uri] = fh.read().splitlines()
            except OSError:
                self.cache[uri] = None
        return self.cache[uri]

    def line(self, uri, line_no):
        lines = self._load(uri)
        if not lines or line_no < 1 or line_no > len(lines):
            return ""
        return lines[line_no - 1].strip()


def build_rule_index(run):
    """Map ruleId/index -> rule object for title, CWE and remediation lookup."""
    rules = run.get("tool", {}).get("driver", {}).get("rules", [])
    by_id = {r.get("id"): r for r in rules}
    return rules, by_id


def get_rule(result, rules, by_id):
    rid = result.get("ruleId")
    if rid in by_id:
        return by_id[rid]
    idx = result.get("ruleIndex")
    if isinstance(idx, int) and 0 <= idx < len(rules):
        return rules[idx]
    return {}


def physical(loc):
    """Return (uri, start_line) for a SARIF location, or (None, None)."""
    phys = loc.get("physicalLocation", {})
    uri = phys.get("artifactLocation", {}).get("uri")
    line = phys.get("region", {}).get("startLine")
    return uri, line


def extract_flow_steps(result):
    """Flatten the primary code flow into ordered, de-duplicated steps."""
    flows = result.get("codeFlows") or []
    if not flows:
        return []
    thread_flows = flows[0].get("threadFlows") or []
    if not thread_flows:
        return []
    steps = []
    prev = None
    for tf_loc in thread_flows[0].get("locations", []):
        uri, line = physical(tf_loc.get("location", {}))
        if uri is None or line is None:
            continue
        key = (uri, line)
        if key == prev:  # collapse consecutive repeats of the same line
            continue
        prev = key
        steps.append((uri, line))
    return steps


def render_flow(steps, reader, project_root):
    """Render the full source-to-sink path with code snippets, one step per line."""
    lines = []
    multi_file = len({uri for uri, _ in steps}) > 1
    for i, (uri, line_no) in enumerate(steps, 1):
        code = reader.line(uri, line_no)
        ref = f"{uri}:{line_no}" if multi_file else f"L{line_no}"
        lines.append(f"{i}. {ref}  |  {code}")
    return "\n".join(lines)


def endpoint(steps, reader, which):
    """Format the source (first) or sink (last) step as 'file:line | code'."""
    if not steps:
        return ""
    uri, line_no = steps[0] if which == "source" else steps[-1]
    code = reader.line(uri, line_no)
    return f"{uri}:{line_no}  |  {code}".rstrip(" |")


def result_to_row(result, rules, by_id, reader, project_root):
    rule = get_rule(result, rules, by_id)
    props = result.get("properties", {}) or {}

    uri, line = physical(result.get("locations", [{}])[0]) if result.get("locations") else (None, None)
    severity = LEVEL_TO_SEVERITY.get(result.get("level"), result.get("level", ""))
    cwes = ", ".join(rule.get("properties", {}).get("cwe", []) or [])

    steps = extract_flow_steps(result)

    return {
        "severity": severity,
        "issue_title": rule.get("shortDescription", {}).get("text", rule.get("name", "")),
        "rule_id": result.get("ruleId", ""),
        "cwe": cwes,
        "priority_score": props.get("priorityScore", ""),
        "file": uri or "",
        "line": line or "",
        "message": result.get("message", {}).get("text", ""),
        "source": endpoint(steps, reader, "source"),
        "sink": endpoint(steps, reader, "sink"),
        "data_flow": render_flow(steps, reader, project_root),
        "remediation": (rule.get("help", {}).get("markdown")
                        or rule.get("help", {}).get("text", "")).strip(),
        "autofixable": props.get("isAutofixable", ""),
        "fingerprint": (result.get("fingerprints", {}) or {}).get("identity", "")
        or (result.get("fingerprints", {}) or {}).get("0", ""),
    }


def sarif_to_rows(sarif, reader, project_root):
    rows = []
    for run in sarif.get("runs", []):
        rules, by_id = build_rule_index(run)
        for result in run.get("results", []):
            rows.append(result_to_row(result, rules, by_id, reader, project_root))
    rows.sort(key=lambda r: (SEVERITY_ORDER.get(r["severity"], 9),
                             r["file"], r["line"] if isinstance(r["line"], int) else 0))
    return rows


def main():
    parser = argparse.ArgumentParser(
        description="Export Snyk Code findings (source-to-sink + remediation) to CSV.",
        epilog="Pass extra Snyk CLI flags after '--', e.g. -- --org=acme --severity-threshold=high",
    )
    parser.add_argument("target", nargs="?", default=".",
                        help="Path to the project to scan (default: current dir)")
    parser.add_argument("-o", "--output", default="snyk-code-results.csv",
                        help="CSV output path (default: snyk-code-results.csv)")
    parser.add_argument("--sarif-input",
                        help="Use an existing SARIF file instead of running a scan")
    parser.add_argument("--project-root",
                        help="Root the SARIF paths are relative to "
                             "(default: target, or sarif file's dir with --sarif-input)")
    parser.add_argument("snyk_args", nargs="*",
                        help="Extra args passed through to `snyk code test`")
    args = parser.parse_args()

    if args.sarif_input:
        sarif_path = validate_input_path(args.sarif_input)
        project_root = args.project_root or os.path.dirname(sarif_path) or "."
    else:
        sarif_path = run_snyk_code(args.target, args.snyk_args)
        project_root = args.project_root or args.target

    with open(sarif_path, "r", encoding="utf-8") as fh:
        sarif = json.load(fh)

    reader = SourceReader(project_root)
    rows = sarif_to_rows(sarif, reader, project_root)

    with open(args.output, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    summary = ", ".join(f"{counts[s]} {s}" for s in ("High", "Medium", "Low") if s in counts)
    print(f"Wrote {len(rows)} issues ({summary or 'none'}) to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
