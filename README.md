# snyk-code-to-csv

Run `snyk code test` and export the results to a **CSV** and/or a **PDF report**
that includes the **full source-to-sink data flow** (with real code snippets)
and the **remediation advice** ("how to fix") for every issue.

## Why SARIF (not `--json` or `snyk-to-html`)

Snyk Code can emit `--json`, `--sarif`, and you can render `snyk-to-html`.
Only **SARIF** carries everything this utility needs in one structured place:

| Need | Where it lives in SARIF |
|------|-------------------------|
| Source → sink data flow | `runs[].results[].codeFlows[].threadFlows[].locations[]` (file + line per step) |
| Remediation / how to fix | `runs[].tool.driver.rules[].help.markdown` |
| CWE / title | `rules[].properties.cwe`, `rules[].shortDescription` |
| Severity | `results[].level` (error→High, warning→Medium, note→Low) |
| Priority score / autofixable | `results[].properties` |

The data-flow steps in SARIF are file+line only (no inline code), so this tool
reads the source files from disk to attach the actual code line to each step.

## Requirements

- [Snyk CLI](https://docs.snyk.io/snyk-cli) authenticated (`snyk auth`)
- Python 3 — CSV export uses the **standard library only**
- For PDF export only: `pip3 install reportlab` (pure Python, no system deps).
  It is imported lazily, so CSV export works without it.

## Usage

```bash
# Scan a project -> snyk-code-results.csv
./snyk_code_to_csv.py /path/to/project

# PDF report instead of CSV  -> snyk-code-results.pdf
./snyk_code_to_csv.py /path/to/project --format pdf

# Both, with a custom base name -> report.csv and report.pdf
./snyk_code_to_csv.py /path/to/project --format both -o report

# Current directory, custom output
./snyk_code_to_csv.py . -o findings.csv

# Re-use an existing SARIF file (no re-scan)
./snyk_code_to_csv.py --sarif-input results.sarif --project-root /path/to/project

# Pass extra flags through to the Snyk CLI (after `--`)
./snyk_code_to_csv.py . -- --org=my-org --severity-threshold=medium
```

### Output formats

`--format {csv,pdf,both}` (default `csv`). With `-o` you give a path/base name;
the extension is set automatically per format (so `-o report --format both`
writes `report.csv` and `report.pdf`).

The **PDF report** has a summary header (project, date, issue counts) followed by
one section per finding: a severity-coloured title, a metadata table
(file:line, rule, CWE, priority score, auto-fixable), the message, the full
numbered source→sink data flow in monospace, and the remediation guidance with
its headings and bullet lists rendered.

> `--project-root` is the directory the SARIF file paths are relative to. It
> defaults to the scan target, so you only need it with `--sarif-input`.
>
> For safety against path traversal, a `--sarif-input` file must live inside the
> current working directory tree. Run the tool from (or above) the directory
> holding your SARIF file, or copy the SARIF in first.

## CSV columns

| Column | Description |
|--------|-------------|
| `severity` | High / Medium / Low |
| `issue_title` | e.g. "SQL Injection" |
| `rule_id` | e.g. `java/Sqli` |
| `cwe` | e.g. `CWE-89` |
| `priority_score` | Snyk priority score (0–1000) |
| `file`, `line` | Primary (sink) location |
| `message` | The finding description |
| `source` | First data-flow step (`file:line | code`) |
| `sink` | Last data-flow step (`file:line | code`) |
| `data_flow` | Full numbered source→sink path with code, one step per line |
| `remediation` | Rule help markdown (Details + best practices) |
| `autofixable` | Whether Snyk can auto-fix it |
| `fingerprint` | Stable issue identity for de-duping across runs |

Rows are sorted by severity, then file, then line.
