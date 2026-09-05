<p align="center">
  <img src="assets/icon.png" width="128" alt="CPGuard"/>
</p>
<h1 align="center">CPGuard</h1>

<p align="center">
  Open-source <b>SAST</b> combining <b>CPG-based taint analysis</b> with <b>LLM triage</b><br/>
  <sub>A desktop security review tool — the pipeline of Fortify, the review ergonomics of Ghidra, offline by default</sub>
</p>

<p align="center">
  <b>English</b> · <a href="README.ko.md">한국어</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white" alt="Windows">
  <img src="https://img.shields.io/badge/Django-5.2-092E20?logo=django&logoColor=white" alt="Django 5.2">
  <img src="https://img.shields.io/badge/languages-11-4da3ff" alt="11 languages">
  <img src="https://img.shields.io/badge/taint%20rules-77-4da3ff" alt="77 taint rules">
  <img src="https://img.shields.io/badge/tests-217%20passing-2e7d32" alt="tests passing">
  <img src="https://img.shields.io/badge/DVWA-recall%20100%25%20·%20precision%2080%25-2e7d32" alt="DVWA benchmark">
  <img src="https://img.shields.io/badge/LLM-Claude%20%C2%B7%20GPT%20%C2%B7%20Gemini-8b5cf6" alt="LLM">
</p>

<p align="center">
  <img src="docs/img/architecture.svg" width="820" alt="CPGuard analysis pipeline"/>
</p>

Pattern-matching SAST drowns you in false positives. CPGuard goes deeper —
**tree-sitter parsing → language-neutral IR → CPG (AST · CFG · def-use · call) → interprocedural taint with function summaries → LLM triage** —
then hands the result to a three-pane review screen where a human confirms the verdict.

<p align="center">
  <img src="docs/img/workbench.png" width="900" alt="CPGuard review screen — Source→Sink taint flow over the code with the inspector"/>
  <br/>
  <sub>Vulnerability review — the <b>Source→Sink</b> taint path highlighted over the real code, with rule, CWE, flow steps and verdict in the inspector.</sub>
</p>

---

## ✨ Features

**Two detection axes**
- **Data flow (taint)** — **11 languages**: JavaScript · TypeScript · PHP · Python · Java · Kotlin · Go · Ruby · C/C++ · Swift · C# (27 file extensions, **77 rules**).
  SQL injection (CWE-89) · command injection (78) · code injection (94) · XSS (79) · path traversal (22) · file inclusion (98) · SSRF (918) · open redirect (601) · insecure deserialization (502) · buffer overflow (120) · format string (134) · LDAP (90) / XPath (643) injection · WebView XSS · Intent redirection (926) · library injection (114).
- **Patterns (single point)** — every language. Hardcoded secrets and vendor keys (798) · PII · TLS verification disabled (295) · weak hash/cipher (327) · predictable RNG (338) · cookie flags (1004) · debug code.

**Vulnerability review screen**
- Three panes: issue explorer (list · table · source tree) / code viewer / inspector.
- Syntax highlighting · command palette (`Ctrl+P`) · context menu · gutter markers.
- **Data-flow visualization** — the Source→Sink step graph stays in sync with the code viewer.
- **AI analysis panel** — asks about the selected issue with its rule, flow and surrounding code attached automatically.
- Verdicts (confirmed / false positive / fixed / deferred) with auditor notes, rows tinted by verdict, an audit-state filter, and new/resolved comparison between scans.

**Scale: one analyst, hundreds of projects**
- **Batch upload** — select many zips at once, or upload a single zip containing project zips; each becomes its own project.
- **Batch progress** — a FIFO worker scans projects sequentially with per-project status.
- **Project portfolio** (`/projects/`) — every project's latest scan in one searchable, sortable, filterable table.
- **Bulk deliverables** — select projects and download one ZIP with each project's PDF report and xlsx sheet, ready to hand to developers.

**LLM triage**
- Claude · ChatGPT (OpenAI) · Gemini. Re-verifies findings for reachability and explains them; provider and model are selectable. Gemini's free tier is enough to try it.

**Deliverables**
- **Assessment report (PDF)** — cover, revision history, table of contents, scope and methodology, severity chart, checklist, per-finding cards (target · description · data-flow steps · impact · remediation · safe example · CWE reference), overall assessment, severity-rating appendix, and an assessment-history table across runs.
- Remediation guide (PDF) · SARIF 2.1.0 · CSV · 14-column analysis sheet (xlsx).
- Report metadata (author, organization, client, assessor, period, version) is filled in from Settings.

**UX & delivery**
- Flat modern-IDE design, four themes (Dark / Light / VS Code / Ghidra).
- **English ⇄ Korean toggle** covering server-rendered content too — rule messages, PDF report, xlsx sheet, CSV and SARIF.
- **Offline, clean-machine install** — a single exe (PyInstaller + Inno Setup); no Python, no internet, no admin rights.
- Native desktop window (WebView2, falls back to the browser) or a browser dashboard.

---

## 🖥 Screens

| Dashboard | Vulnerability explorer (charts · filters · pagination) |
|:---:|:---:|
| ![Dashboard](docs/img/dashboard.png) | ![Explorer](docs/img/charts.png) |
| Status tiles · severity distribution · top rules | Severity donut · top rule/CWE bars · large-result explorer |

<p align="center">
  <img src="docs/img/reports.png" width="780" alt="Reports and exports"/>
  <br/>
  <sub>Reports & exports — per-scan assessment report and remediation guide (PDF), SARIF, CSV, analysis sheet (xlsx).</sub>
</p>

> The review screen (code viewer + Source→Sink flow + inspector) is the hero image above.

---

## 📦 Install

### Installer (recommended — no Python needed)

Download `CPGuard-Setup-0.1.5.exe` from [Releases](https://github.com/KimJeju/cpguard/releases) and run it.
It installs per-user (no admin rights) and installs the WebView2 runtime if missing.

To build the installer yourself:

```powershell
powershell -ExecutionPolicy Bypass -File packaging/build.ps1
```

It also runs portable — copy the `dist/CPGuard` folder and run `CPGuard.exe`.

### From source (development)

```bash
pip install .
cpguard --help
```

## 🚀 Usage

```bash
# CLI scan (SARIF + analysis sheet)
cpguard scan ./project --sarif out.sarif --xlsx out.xlsx

# Re-verify with LLM triage
cpguard scan ./project --triage --provider gemini

# Web dashboard (browser)
cpguard serve

# Native desktop window
cpguard app
```

In the dashboard: upload zip(s) → progress screen (step checklist + runtime log) → review and mark verdicts →
add an LLM key in ⚙️ Settings to enable AI analysis and triage.

## 🔁 CI/CD (GitHub Actions)

Scan on every push and PR, upload SARIF to **GitHub Code Scanning** so new findings appear inline on the code and the PR. A severity gate can fail the build.

```yaml
# .github/workflows/cpguard.yml
permissions:
  contents: read
  security-events: write
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: cpguard
        uses: KimJeju/cpguard@v0.1.5
        with:
          path: '.'
          fail-on: 'high'      # fail the build on high or above (none = no gate)
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: '${{ steps.cpguard.outputs.sarif }}' }
```

The CLI gates too: `cpguard scan . --sarif out.sarif --fail-on high` (exit code 1 at or above that severity).
This repository's [`.github/workflows/cpguard.yml`](.github/workflows/cpguard.yml) is a working example.

---

## 🧱 Architecture

```
tree-sitter → language-neutral IR → CPG (AST · CFG · def-use · call) → interprocedural taint (function summaries)
                                                                ↘ LLM triage → review screen / reports
pattern axis, every language (secrets · PII · config) ─────────↗
```

- **Sound over-approximation** — both branches merged, summary fixpoint (recursion and mutual recursion), unknown functions pass taint through.
- **Integrity reporting** — "0 findings" is distinguished from "could not read": parse failures, size limits and syntax errors are recorded and shown.
- **Read-only, evidence-first** — the tool never silently hides a finding; the final verdict is a human's.
- Adding a language is a table, not a fork: one normalizer maps each grammar's nodes onto the shared IR, so the CPG and taint engine stay untouched.

Stack: Python 3.11+ · tree-sitter (11 languages) · Django (SSR) · reportlab (PDF) · openpyxl (xlsx) · SARIF 2.1.0 · LLM SDKs (anthropic / openai / google-genai) · pytest.

## 📊 Accuracy

Measured against DVWA's labelled vulnerable/safe pairs: **recall 100% · precision 80% · F1 0.889** on the per-file measurable data-flow modules (N=4). Methodology and limitations are disclosed in [`bench/README.md`](bench/README.md) — the labelled set is small, and sanitizer recognition is the next improvement.

## 📈 Large codebases

Strategies for extreme scale (20–30 GB of source, 50k+ findings) — sink pre-filtering, incremental and summary caches, the finding DB table, aggregation with virtual scrolling, triage clustering — are in [`docs/large-scale.md`](docs/large-scale.md).

## 🗺️ Roadmap

- [x] Taint core, pattern engine, LLM triage, review screen
- [x] PDF assessment report and remediation guide · offline installer
- [x] Finding DB table + server-side pagination · virtual scrolling for large results
- [x] Sink pre-filtering · multiprocessing · parse/summary caches · triage clustering
- [x] CI/CD — GitHub Action · SARIF → Code Scanning · severity gate
- [x] Accuracy benchmark (DVWA) published — recall 100% · precision 80% ([details](bench/README.md))
- [x] 11 languages — Java, Kotlin, Go, Ruby, C/C++, Swift, C# added
- [x] Batch scanning, project portfolio and bulk deliverables for hundreds of projects
- [ ] Stronger sanitizer recognition · OWASP Benchmark coverage

## 📄 License

An open-source project for education and research (capstone). A license file will be added.
