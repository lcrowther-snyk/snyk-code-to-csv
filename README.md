# snyk-code-to-csv

Run Snyk **Code** (SAST) and/or **Open Source** (SCA) tests and export the
results to **CSV**, a **PDF report**, and/or a **Word (DOCX) report**. Each
finding includes the full **source-to-sink data flow** (Code, with real code
snippets) or **dependency path** (SCA), plus the **remediation advice** ("how to
fix") — all in one unified report.

## What each scan contributes

`--type` selects which tests run: `code` (default), `sca`, or `both`. Both kinds
of finding land in the **same** output file, tagged with a `scan_type` column.

| | Snyk **Code** (`snyk code test`) | Snyk **Open Source / SCA** (`snyk test`) |
|---|---|---|
| Flags | a vulnerable line of source | a vulnerable dependency `pkg@version` |
| "source → sink" | taint data flow with code snippets | dependency path (`from[]` — how it's pulled in) |
| How to fix | rule best-practices guidance | upgrade to the `fixedIn` version / upgrade path |
| IDs | CWE | CWE **+ CVE + CVSS score** |
| Source format | SARIF (`--sarif`) | JSON (`--json`) |

### Why these formats

For **Code**, SARIF is the only format carrying the data flow
(`codeFlows[].threadFlows[].locations[]`) *and* remediation
(`rules[].help.markdown`) in one place. SARIF gives file+line per step only, so
the tool reads the source files from disk to attach the real code line.

For **SCA**, the JSON output is the richest — it carries the dependency path
(`from[]`), `fixedIn` / `upgradePath`, CVE/CVSS, and exploit maturity that the
SCA SARIF omits.

## Requirements

- [Snyk CLI](https://docs.snyk.io/snyk-cli) authenticated (`snyk auth`)
- For SCA (`--type sca`/`both`): the project's package manifests / lockfiles
  (e.g. `pom.xml`, `package-lock.json`) must be present so `snyk test` can resolve dependencies
- Python 3 — CSV export uses the **standard library only**
- For PDF export only: `pip3 install reportlab` (pure Python, no system deps).
- For DOCX export only: `pip3 install python-docx` (pure Python, no system deps).

  Both report libraries are imported lazily, so CSV export works without them
  and each report format only needs its own library installed.

## Usage

```bash
# Snyk Code scan -> snyk-results.csv (default --type code)
./snyk_code_to_csv.py /path/to/project

# Open-source / SCA scan only
./snyk_code_to_csv.py /path/to/project --type sca

# Both Code and SCA in one unified report
./snyk_code_to_csv.py /path/to/project --type both --format pdf -o report

# Formats: pdf, docx, all, or a comma-separated list
./snyk_code_to_csv.py /path/to/project --format docx
./snyk_code_to_csv.py /path/to/project --type both --format all -o report
./snyk_code_to_csv.py /path/to/project --format csv,docx -o report

# Re-use an existing Snyk Code SARIF file (no re-scan; --type code)
./snyk_code_to_csv.py --sarif-input results.sarif --project-root /path/to/project

# Pass extra flags through to the Snyk CLI (after `--`)
./snyk_code_to_csv.py . --type both -- --org=my-org --severity-threshold=high
```

### Output formats

`--format` accepts `csv`, `pdf`, `docx`, `all`, or a comma-separated list such
as `csv,docx` (default `csv`). With `-o` you give a path/base name; the
extension is set automatically per format (so `-o report --format all` writes
`report.csv`, `report.pdf`, and `report.docx`).

The **PDF** and **DOCX** reports share the same structure: a summary header
(project, scan type, date, issue counts) followed by one section per finding — a
severity- and type-tagged title (`[High] [Code]`, `[Critical] [SCA]`), a
metadata table, the message, the numbered data flow / dependency path in
monospace, and the remediation guidance with headings and bullet lists rendered.
The metadata table and flow label adapt to the finding type (data flow + rule
for Code; dependency path + package/CVE/CVSS/fixed-in for SCA).

> `--project-root` is the directory the SARIF file paths are relative to. It
> defaults to the scan target, so you only need it with `--sarif-input`.
>
> For safety against path traversal, a `--sarif-input` file must live inside the
> current working directory tree. Run the tool from (or above) the directory
> holding your SARIF file, or copy the SARIF in first.

## CSV columns

The CSV is a unified superset; columns that don't apply to a finding's
`scan_type` are left blank (e.g. `cve`/`cvss`/`package` are SCA-only,
`priority_score`/`autofixable` are Code-only).

| Column | Applies to | Description |
|--------|-----------|-------------|
| `scan_type` | both | `Code` or `SCA` |
| `severity` | both | Critical / High / Medium / Low |
| `issue_title` | both | e.g. "SQL Injection" |
| `rule_id` | both | Code rule (`java/Sqli`) or Snyk vuln ID (`SNYK-JAVA-...`) |
| `cwe` | both | e.g. `CWE-89` |
| `cve` | SCA | e.g. `CVE-2026-8178` |
| `cvss` | SCA | CVSS score |
| `package` | SCA | Vulnerable `package@version` |
| `fixed_in` | SCA | Version(s) that contain the fix |
| `exploit_maturity` | SCA | e.g. "Mature", "Not Defined" |
| `priority_score` | Code | Snyk priority score (0–1000) |
| `file`, `line` | both | Code: sink location. SCA: manifest file |
| `message` | both | The finding description |
| `source` | both | First flow step — Code: `file:line | code`; SCA: top-level dependency |
| `sink` | both | Last flow step — Code: the sink; SCA: the vulnerable package |
| `data_flow` | both | Code: numbered source→sink path with code. SCA: dependency path |
| `remediation` | both | Code: rule best-practices. SCA: upgrade advice + introduced-through + description |
| `autofixable` | Code | Whether Snyk can auto-fix it |
| `fingerprint` | both | Stable issue identity for de-duping across runs |

Rows are sorted by severity (Critical first), then scan type, then file.
