<p align="center">
  <img src="assets/icon.png" width="128" alt="CPGuard"/>
</p>
<h1 align="center">CPGuard</h1>

<p align="center">
  <b>Air-gapped security assessment, from source code to the finished report</b><br/>
  <sub>CPG-based taint analysis · LLM triage · audit deliverables generated for you — a desktop tool that never phones home</sub>
</p>

<p align="center">
  <b>English</b> · <a href="README.ko.md">한국어</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Platform-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-0078D6" alt="Windows / macOS / Linux">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0">
  <img src="https://img.shields.io/badge/Django-5.2-092E20?logo=django&logoColor=white" alt="Django 5.2">
  <img src="https://img.shields.io/badge/languages-11-4da3ff" alt="11 languages">
  <img src="https://img.shields.io/badge/taint%20rules-78-4da3ff" alt="78 taint rules">
  <img src="https://img.shields.io/badge/tests-253%20passing-2e7d32" alt="tests passing">
  <img src="https://img.shields.io/badge/OWASP%20Benchmark-Java%200.801%20·%20Python%200.717-2e7d32" alt="OWASP Benchmark">
  <img src="https://img.shields.io/badge/LLM-Claude%20%C2%B7%20GPT%20%C2%B7%20Gemini-8b5cf6" alt="LLM">
</p>

<p align="center">
  <img src="docs/img/architecture.svg" width="820" alt="CPGuard analysis pipeline"/>
</p>

> **CPGuard** = **CPG** (Code Property Graph) + **Guard** — it guards your code with a property graph, not a pattern list. That graph is why the logo is three connected nodes.

Pattern-matching scanners drown you in false positives. CPGuard goes deeper —
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
- **Data flow (taint)** — **11 languages**: JavaScript · TypeScript · PHP · Python · Java · Kotlin · Go · Ruby · C/C++ · Swift · C# (27 file extensions, **78 rules**).
  SQL injection (CWE-89) · command injection (78) · code injection (94) · XSS (79) · path traversal (22) · file inclusion (98) · SSRF (918) · open redirect (601) · insecure deserialization (502) · buffer overflow (120) · format string (134) · LDAP (90) / XPath (643) injection · WebView XSS · Intent redirection (926) · library injection (114).
- **Patterns (single point)** — every language. Hardcoded secrets and vendor keys (798) · PII · TLS verification disabled (295) · weak hash/cipher (327) · predictable RNG (338) · cookie flags (1004) · debug code.

**Vulnerability review screen**
- Three panes: issue explorer (list · table · source tree) / code viewer / inspector.
- Syntax highlighting · command palette (`Ctrl+P`) · context menu · gutter markers.
- **Data-flow visualization** — the Source→Sink step graph stays in sync with the code viewer.
- **AI analysis panel** — asks about the selected issue with its rule, flow and surrounding code attached automatically.
- Verdicts (confirmed / false positive / fixed / deferred) with auditor notes, rows tinted by verdict, an audit-state filter, and new/resolved comparison between scans.
- **A verdict moves the numbers immediately** — marking a finding a false positive, deferred or fixed drops the open count and the severity badges on the spot. The detection total stays: it is what the scan found, and a person's verdict does not change that.
- **A rescan inherits the previous verdicts** — same fingerprint (rule, file, normalised sink code), same audit state and note. The second and third round of an assessment no longer re-judge what was already cleared.
- **Judge the whole filtered list at once** — findings arrive in clusters of the same sink, and nobody clicks through them one at a time.
- **Filter by what is inside the flow** — match calls and variables along the traced path (whole flow / source / sink, contains or not, regex allowed). Narrow to flows that went through `sanitize`, then clear them in one action.
- **Uncertain flows are marked** — a flow that passed through a function whose code is not in the analysed set is flagged and filterable, which is the pile to review first.
- Similar-issue grouping (same rule, same sink), verdict history (from what, to what, when), and save-and-next.

**Running an assessment**
- **Cancel a scan or a batch** — a run started by mistake stops instead of being waited out.
- **Get back to a running scan** — a sticky bar links to it from any screen.
- **Delete scans in bulk** — a bad batch leaves hundreds of rows behind.
- **Per-project exclusions** — path globs, rules and the stated reason are saved and applied to the next scan, and excluded files are never parsed. What was applied is stored on the scan, so the report reflects the run that produced it.

**Scale: one analyst, hundreds of projects**
- **Batch upload** — select many zips at once, or upload a single zip containing project zips; each becomes its own project.
- **Batch progress** — a FIFO worker scans projects sequentially with per-project status.
- **Project portfolio** (`/projects/`) — every project's latest scan in one searchable, sortable, filterable table.
- **Bulk deliverables** — select projects and download one ZIP with each project's PDF report and xlsx sheet, ready to hand to developers.

**Assess against the standard your client asks for**
- Tick the references before the scan starts: **MOIS Secure Coding Guide** (Korea's public-sector standard) · **Electronic Financial Supervision Regulation** web checklist (Korean finance) · **Mobile secure coding checklist** (draft) · **OWASP Top 10 (2021)** · **CWE**. Pick several — real Korean deliverables report against more than one at a time.
- The mapping key is CWE, so **the scan runs once and the standards only shape the report** — switching or adding references never means rescanning.
- Filter the review screen by check item, group the issue list by it, and tick which standards each export carries. The report's *check items* section becomes those standards' full checklists with a verdict per item, and the xlsx gains a *check items* sheet. Items are identified by category and weakness name, the way real assessment deliverables are written — never by an item number, which differs between editions of the guide. Items that were assessed and came back clean stay in the table — that is the evidence of what was checked.
- **A check item with no rule behind it is never reported as "pass."** Items outside static analysis — directory indexing, admin page exposure, CSRF — are marked *Not assessed*, so the deliverable never claims a check that did not happen.
- Findings outside the chosen standard's mapping are reported separately, never silently dropped.

**Deliverables you can actually hand over**
- **Consolidated assessment report** — tick the projects on the Reports screen and get one submission-ready document covering all of them: purpose and legal basis, schedule, tool, assessor, the standards' check items, **initial findings → false-positive review → final items to remediate**, per-project detail (files, lines of code, languages, weaknesses by severity), remediation by type, and appendices. Structured like the reports Korean assessment firms actually deliver.
- **Report templates** — name a template and it decides which sections ship (detail, source and flow, reviewer comment, exclusions, applied rules, scope by language) plus the cover title, header note and logo. Client requirements differ and templates pile up per contract.
- **Exclusions, applied rules and scope appendices** — what was excluded and why, every rule applied including the ones with no findings, and files/lines/findings/density per language. On a checklist-shaped deliverable "we checked and found nothing" carries as much weight as a finding.
- **The review verdicts become the report.** Marking a finding as a false positive or excluding it on the review screen — with the note explaining why — is what turns a raw scanner dump into a deliverable. Section 3.2 is built from exactly those verdicts, and the initial/final totals differ accordingly.
- **Word (.docx) and PDF.** The Word file is the editable master, so the analyst can drop it into the client's template, add on-site opinions, and ship it. Same sections, same tables, same wording as the PDF.
- **Analysis sheet (xlsx)** — the fixed 14-column format Korean clients expect, plus a *check items* sheet.
- Everything is **black text on light grey**. Assessment reports travel as black-and-white printouts and photocopies and get pasted into the client's own template, so nothing is distinguished by colour alone — severity is graded by lightness, verdicts read as words.

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

### Installer — Windows (recommended, no Python needed)

Download `CPGuard-Setup-0.1.3.exe` from [Releases](https://github.com/KimJeju/cpguard/releases) and run it.
It installs per-user (no admin rights) and installs the WebView2 runtime if missing.

To build the installer yourself:

```powershell
powershell -ExecutionPolicy Bypass -File packaging/build.ps1
```

It also runs portable — copy the `dist/CPGuard` folder and run `CPGuard.exe`.

### From source — Windows · macOS · Linux

```bash
pip install .
cpguard --help
```

The engine, the web UI and every report format are pure Python and run on all three platforms.
Only the packaged installer and the native desktop window (WebView2) are Windows-specific.
Korean text in PDF reports needs a Korean font: Windows and macOS have one out of the box, on
Linux install `fonts-nanum`, or point `CPGUARD_PDF_FONT` at any TrueType font you prefer.

## 🚀 Usage

```bash
# CLI scan (SARIF + analysis sheet)
cpguard scan ./project --sarif out.sarif --xlsx out.xlsx

# Assess against one or more standards (mois | efs | owasp | cwe)
cpguard scan ./project --standard mois --standard efs --xlsx out.xlsx

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
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: cpguard
        uses: KimJeju/cpguard@v0.1.3
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

Measured against **labelled ground truth in eight languages** — five corpora totalling 138,785 cases, of which **76,866 are scored** (the rest are categories excluded below). Score = recall − false-positive rate (the official OWASP metric; random guessing = 0.000).

| Corpus | Language | Scored | Recall | Precision | Score |
|---|---|---:|---:|---:|---:|
| OWASP Benchmark v1.2 | Java | 1,572 | 93.4% | 88.4% | **0.801** |
| OWASP Benchmark for Python | Python | 346 | 82.1% | 83.3% | **0.717** |
| BenchProctor (express) | TypeScript / JavaScript | 2,200 | ~56% | ~75% | **0.375** |
| PHP Vulnerability test suite | PHP | 31,824 | 47.0% | 66.4% | **0.369** |
| BenchProctor (rails / sinatra) | Ruby | 2,400 | ~53% | ~76% | **0.36** |
| C# Vulnerability Test Suite | C# | 33,024 | 30.0% | 87.8% | **0.242** |
| BenchProctor (standalone) | C / C++ | 1,300 | ~57% | ~57% | **0.13** |
| BenchProctor (gin / net_http) | Go | 2,000 | ~35% | ~53% | **0.045** |

Read it plainly: **Java and Python are at working-tool quality; JS/TS, Ruby and PHP are usable; C#, C/C++ and Go are not there yet.** Kotlin and Swift have no public labelled corpus at all, so they are covered by idiom tests instead (see below).

Config-only categories (`weakrand`, `crypto`, `hash`, `securecookie`, `trustbound`) are not data-flow problems and are excluded rather than counted as free wins. Categories that *are* data-flow problems but that CPGuard has no rule for (NoSQL injection, SSTI, prototype pollution, XXE …) are reported **separately** from those, so coverage is not quietly inflated.

**The benchmarks drove real engine work.** Java started at 0.137 and PHP at 0.001; every point since came from a defect the numbers exposed — taint dying inside `try` blocks, for-each variables losing the collection's taint, no path sensitivity at all, container mutations not propagating, comparison results carrying taint, constructor-to-field-to-method flows missing in every language, and by-reference output parameters (`fgets(buf, …)`) invisible to a return-value-only model. Each fix is a general analysis technique, not a tweak aimed at the test cases. The full before/after ledger is in [`bench/README.md`](bench/README.md).

**Where labelled data does not exist** (Kotlin, Swift, and any framework a corpus does not cover), CPGuard ships **idiom tests** instead: 130 minimal reproductions of shapes that are common in real code, run as part of the test suite. They catch a different class of defect than the benchmarks do — TypeScript parameters were carrying their type annotation into the parameter name, which silently removed *every typed function* from interprocedural analysis, and no benchmark score moved when it was fixed.

A second measurement on a real application (DVWA, PHP) is also published. Full methodology, per-category tables and limitations: [`bench/README.md`](bench/README.md).

## 📈 Large codebases

Strategies for extreme scale (20–30 GB of source, 50k+ findings) — sink pre-filtering, incremental and summary caches, the finding DB table, aggregation with virtual scrolling, triage clustering — are in [`docs/large-scale.md`](docs/large-scale.md).

## 🗺️ Roadmap

- [x] Taint core, pattern engine, LLM triage, review screen
- [x] PDF assessment report and remediation guide · offline installer
- [x] Finding DB table + server-side pagination · virtual scrolling for large results
- [x] Sink pre-filtering · multiprocessing · parse/summary caches · triage clustering
- [x] CI/CD — GitHub Action · SARIF → Code Scanning · severity gate
- [x] Accuracy measured in 8 languages — 5 labelled corpora, 76,866 scored cases ([details](bench/README.md))
- [x] 11 languages — Java, Kotlin, Go, Ruby, C/C++, Swift, C# added
- [x] Batch scanning, project portfolio and bulk deliverables for hundreds of projects
- [x] Constant propagation · container taint · key-sensitive map tracking
- [x] Verdict inheritance across rescans, bulk verdicts, flow-content filter, verdict history
- [x] Per-project exclusions, report templates, scope/exclusion/applied-rule appendices
- [ ] Framework-aware entry points (Spring, JPA) · stronger sanitizer recognition

## 📄 License

[Apache License 2.0](LICENSE). Free to use, modify and redistribute, commercially included, provided the notice and license are preserved. Includes an express patent grant.

Bundled third-party font: **NanumGothic** (c) NHN Corporation, under the [SIL Open Font License 1.1](cpguard/report/fonts/OFL.txt). It ships with the package so Korean reports render on servers without Korean fonts installed.
