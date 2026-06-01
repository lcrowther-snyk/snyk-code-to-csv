#!/usr/bin/env python3
"""
snyk_code_to_csv.py

Run `snyk code test` and export the findings to a CSV and/or a PDF report that
includes the full source-to-sink data flow (with real code snippets) and the
remediation advice ("how to fix") for every issue.

Output is built from Snyk Code's SARIF output, which is the only format that
carries both the data-flow steps (codeFlows/threadFlows) and the per-rule
remediation guidance (rule.help.markdown).

Usage:
    # Scan a project and write snyk-code-results.csv
    ./snyk_code_to_csv.py /path/to/project

    # Produce a PDF report instead (or both)
    ./snyk_code_to_csv.py /path/to/project --format pdf
    ./snyk_code_to_csv.py /path/to/project --format both -o report

    # Re-use an existing SARIF file instead of scanning
    ./snyk_code_to_csv.py --sarif-input results.sarif --project-root /path/to/project

    # Custom output path and pass extra args through to the Snyk CLI
    ./snyk_code_to_csv.py . -o findings.csv -- --org=my-org --severity-threshold=medium

CSV export uses only the standard library. PDF export additionally requires
`reportlab` (pip3 install reportlab); it is imported lazily so CSV works without it.

Snyk CLI exit codes: 0 = no issues, 1 = issues found (both are success here),
2 = scan error.
"""

import argparse
import csv
import datetime
import json
import os
import re
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


def severity_counts(rows):
    counts = {}
    for r in rows:
        counts[r["severity"]] = counts.get(r["severity"], 0) + 1
    return counts


def summary_text(rows):
    counts = severity_counts(rows)
    return ", ".join(f"{counts[s]} {s}" for s in ("High", "Medium", "Low") if s in counts)


def write_csv(rows, path):
    with open(path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


# --- PDF export ------------------------------------------------------------

SEVERITY_COLORS = {"High": "#d1352c", "Medium": "#d98c00", "Low": "#3b7dd8"}


def _escape(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def _inline_md(text):
    """Convert inline markdown to reportlab's mini-markup (after escaping)."""
    out = _escape(text)
    out = re.sub(r"`([^`]+)`",
                 r'<font face="Courier" backColor="#f0f0f0">\1</font>', out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", out)
    out = re.sub(r"\[([^\]]+)\]\(([^)]+)\)",
                 r'<a href="\2" color="#3b7dd8">\1</a>', out)
    return out


def _wrap_mono(text, width=108):
    """Hard-wrap monospace text so long lines (e.g. SQL) don't overflow the page."""
    import textwrap
    wrapped = []
    for line in text.split("\n"):
        if len(line) <= width:
            wrapped.append(line)
        else:
            wrapped.extend(textwrap.wrap(
                line, width=width, subsequent_indent="      ",
                break_long_words=True, break_on_hyphens=False) or [""])
    return "\n".join(wrapped)


def _markdown_to_flowables(md, styles):
    from reportlab.platypus import Paragraph, Spacer, Preformatted, ListFlowable, ListItem

    flow, bullets, para = [], [], []

    def flush_para():
        if para:
            flow.append(Paragraph(_inline_md(" ".join(s.strip() for s in para)), styles["body"]))
            para.clear()

    def flush_bullets():
        if bullets:
            items = [ListItem(Paragraph(_inline_md(b), styles["body"])) for b in bullets]
            flow.append(ListFlowable(items, bulletType="bullet", leftIndent=14))
            flow.append(Spacer(1, 4))
            bullets.clear()

    lines = md.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.lstrip().startswith("```"):
            flush_para(); flush_bullets()
            code, i = [], i + 1
            while i < len(lines) and not lines[i].lstrip().startswith("```"):
                code.append(lines[i]); i += 1
            flow.append(Preformatted(_wrap_mono("\n".join(code)), styles["code"]))
            flow.append(Spacer(1, 4))
            i += 1
            continue
        stripped = line.strip()
        if not stripped:
            flush_para(); flush_bullets()
            i += 1
            continue
        h = re.match(r"^(#{1,6})\s+(.*)", stripped)
        if h:
            flush_para(); flush_bullets()
            style = styles["h2"] if len(h.group(1)) <= 2 else styles["h3"]
            flow.append(Paragraph(_inline_md(h.group(2)), style))
            i += 1
            continue
        b = re.match(r"^[-*]\s+(.*)", stripped)
        if b:
            flush_para()
            bullets.append(b.group(1))
            i += 1
            continue
        flush_bullets()
        para.append(line)
        i += 1
    flush_para(); flush_bullets()
    return flow


def _pdf_styles():
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors

    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle("title", parent=base["Title"], fontSize=20, spaceAfter=4),
        "meta": ParagraphStyle("meta", parent=base["Normal"], fontSize=9,
                               textColor=colors.HexColor("#666666")),
        "finding": ParagraphStyle("finding", parent=base["Heading2"], fontSize=13, spaceBefore=8, spaceAfter=2),
        "h2": ParagraphStyle("h2", parent=base["Heading3"], fontSize=11, spaceBefore=6, spaceAfter=2),
        "h3": ParagraphStyle("h3", parent=base["Heading4"], fontSize=10, spaceBefore=4, spaceAfter=2),
        "label": ParagraphStyle("label", parent=base["Normal"], fontSize=9, fontName="Helvetica-Bold",
                                textColor=colors.HexColor("#444444"), spaceBefore=4),
        "body": ParagraphStyle("body", parent=base["Normal"], fontSize=9.5, leading=13),
        "code": ParagraphStyle("code", parent=base["Code"], fontSize=7.2, leading=9,
                               backColor=colors.HexColor("#f5f5f5"), borderPadding=4,
                               textColor=colors.HexColor("#1a1a1a")),
    }


def write_pdf(rows, path, meta):
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                         Preformatted, Table, TableStyle, HRFlowable)
    except ImportError:
        raise SystemExit(
            "PDF export requires the 'reportlab' package. Install it with:\n"
            "    pip3 install reportlab"
        )

    styles = _pdf_styles()
    doc = SimpleDocTemplate(path, pagesize=A4, title="Snyk Code Report",
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm)
    story = []

    # Header
    story.append(Paragraph("Snyk Code Security Report", styles["title"]))
    story.append(Paragraph(
        f"Project: {_escape(meta['project'])}<br/>"
        f"Generated: {meta['date']}<br/>"
        f"Total issues: {len(rows)} ({summary_text(rows) or 'none'})", styles["meta"]))
    story.append(Spacer(1, 8))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#cccccc")))

    for idx, r in enumerate(rows, 1):
        sev = r["severity"]
        color = colors.HexColor(SEVERITY_COLORS.get(sev, "#666666"))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f'<font color="{SEVERITY_COLORS.get(sev, "#666666")}">[{sev}]</font> '
            f'{idx}. {_escape(r["issue_title"])}', styles["finding"]))

        info = [
            ["File", f'{r["file"]}:{r["line"]}'],
            ["Rule", r["rule_id"]],
            ["CWE", r["cwe"] or "-"],
            ["Priority score", str(r["priority_score"]) or "-"],
            ["Auto-fixable", str(r["autofixable"]) or "-"],
        ]
        tbl = Table([[k, v] for k, v in info], colWidths=[28 * mm, 146 * mm])
        tbl.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#444444")),
            ("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#eeeeee")),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ]))
        story.append(tbl)

        if r["message"]:
            story.append(Paragraph(_inline_md(r["message"]), styles["body"]))

        story.append(Paragraph("Data flow (source &rarr; sink)", styles["label"]))
        story.append(Preformatted(_wrap_mono(r["data_flow"] or "(no data flow)"), styles["code"]))

        if r["remediation"]:
            story.append(Paragraph("Remediation", styles["label"]))
            story.extend(_markdown_to_flowables(r["remediation"], styles))

        story.append(Spacer(1, 6))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#dddddd")))

    if not rows:
        story.append(Spacer(1, 12))
        story.append(Paragraph("No issues found.", styles["body"]))

    doc.build(story)


def resolve_outputs(output_arg, fmt):
    """Map --output + --format to concrete csv/pdf paths."""
    base = output_arg or "snyk-code-results"
    base = re.sub(r"\.(csv|pdf)$", "", base, flags=re.IGNORECASE)
    targets = {}
    if fmt in ("csv", "both"):
        targets["csv"] = base + ".csv"
    if fmt in ("pdf", "both"):
        targets["pdf"] = base + ".pdf"
    return targets


def main():
    parser = argparse.ArgumentParser(
        description="Export Snyk Code findings (source-to-sink + remediation) to CSV and/or PDF.",
        epilog="Pass extra Snyk CLI flags after '--', e.g. -- --org=acme --severity-threshold=high",
    )
    parser.add_argument("target", nargs="?", default=".",
                        help="Path to the project to scan (default: current dir)")
    parser.add_argument("-f", "--format", choices=("csv", "pdf", "both"), default="csv",
                        help="Output format(s) to write (default: csv)")
    parser.add_argument("-o", "--output",
                        help="Output path/base name (extension is set per format; "
                             "default: snyk-code-results)")
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
    targets = resolve_outputs(args.output, args.format)

    written = []
    if "csv" in targets:
        write_csv(rows, targets["csv"])
        written.append(targets["csv"])
    if "pdf" in targets:
        meta = {"project": os.path.abspath(project_root),
                "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
        write_pdf(rows, targets["pdf"], meta)
        written.append(targets["pdf"])

    print(f"Wrote {len(rows)} issues ({summary_text(rows) or 'none'}) to "
          f"{', '.join(written)}", file=sys.stderr)


if __name__ == "__main__":
    main()
