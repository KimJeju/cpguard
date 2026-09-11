# CPGuard 홍보 키트

릴리스 v0.1.4 기준. 아래 초안은 그대로 복붙하거나 다듬어 쓰면 됩니다.
repo: https://github.com/KimJeju/cpguard

## 한 줄 포지셔닝

> **CPGuard — CPG 기반 taint 분석 + LLM 트리아지를 결합한 오픈소스 SAST.**
> 정규식 패턴이 아니라 코드 속성 그래프로 Source→Sink 흐름을 추적해 오탐을 줄이고,
> Ghidra/Fortify 결의 3분할 감사 작업대에서 조사·판정까지 연결한다. 완전 오프라인 동작.

한 줄 영어:
> An open-source SAST that combines **CPG-based taint analysis with LLM triage** — traces
> real Source→Sink data flow (not regex), triages false positives with Claude/Gemini/GPT,
> and ships a Ghidra-style audit workbench. Runs fully offline.

## 차별점 (talking points)

- **CPG + interprocedural taint** — AST·CFG·def-use·call 그래프로 함수 간 흐름 추적. 패턴 매칭보다 정확.
- **LLM 트리아지** — Claude / Gemini / GPT 로 각 이슈 도달 가능성 재검증 → 오탐 감소.
- **감사 작업대** — 코드 뷰어 위 Source→Sink 흐름 강조 + 인스펙터 + 사람 판정/메모.
- **완전 오프라인** — 파이썬·인터넷·관리자 권한 없이 단일 설치본. 에어갭 환경 OK.
- **대형 코드베이스** — 26,049 파일 / 2.3GB 프로젝트를 ~5분에 4,857건 탐지(실측).
- **정확도(측정치)** — 라벨링 정답지 **8개 언어 5개 코퍼스 138,785건(채점 76,866건)**. 자바 점수 **0.826**(F1 0.921) · C++ **0.79** · 파이썬 **0.717** · Go **0.57** · C **0.52** · JS **0.43** · Ruby **0.42** · TS **0.41** · PHP **0.369** · C# **0.245**. 언어 편차가 크다는 사실을, 그리고 **C·C++ 의 오탐 0 이 작은 코퍼스의 생성 규칙을 맞힌 결과에 가깝다는 것**도 그대로 공개한다. 측정 코드·정답지·제외 기준 전부 공개(`bench/`).
- **CI 연동** — GitHub Action + SARIF → Code Scanning. `fail-on` 게이트.
- **언어** — JS/TS · PHP · Python · Java · Kotlin · Go · Ruby · C/C++ · Swift · C#.
- 오픈소스(졸업작품에서 출발).

---

## Show HN (Hacker News)

**Title:**
`Show HN: CPGuard – open-source SAST that traces source-to-sink with a code property graph`

대안(더 짧게): `Show HN: CPGuard – code property graph SAST with LLM triage, runs offline`

**Body:**
```
CPGuard is an open-source static analyzer for finding security bugs in source code.

It parses with tree-sitter into a language-neutral IR, builds a code property graph
(AST + CFG + def-use + call), and runs interprocedural taint analysis using function
summaries, so it follows user input from a source to a dangerous sink across files
rather than matching a regex at one line. Optionally it sends each finding to an LLM
(Claude/Gemini/GPT) to judge reachability, which removes some false positives.

Numbers, so you can calibrate. Measured against labelled ground truth in eight
languages (five corpora, 76,866 scored cases), score = recall minus false-positive rate:
Java 0.826 (F1 0.921), C++ 0.79, Python 0.717, Go 0.57, C 0.52, JavaScript 0.43,
Ruby 0.42, TypeScript 0.41, PHP 0.369, C# 0.245. The spread is the honest headline,
and so is this caveat: the C/C++ corpora are small and their safe variants use exactly
two guard idioms, so reading those two took false positives to zero in one step. That
is a measure of matching a generator, not of real-world C. Where a score is low it is
usually recall (C# recalls 30.5%), not noise. I exclude categories that are
API-misuse checks rather than data flow (weak crypto/hash/RNG, cookie flags, trust
boundary), and I report categories that *are* data-flow problems but that I have no
rule for separately from those, so coverage is not quietly inflated. The harness is
in bench/ if you want to re-run any of it.

Findings land in a three-pane audit workbench: issue list, a code viewer that draws
the source-to-sink flow inline, and an inspector where you mark true/false positive
and leave a note. It runs fully offline, single installer, no Python or admin rights;
only the optional LLM triage talks to a network.

Languages: JS/TS, PHP, Python, Java, Kotlin, Go, Ruby, C/C++, Swift, C#. Output is
SARIF (GitHub Code Scanning), plus PDF/xlsx reports for the audit paperwork Korean
clients expect. There is a GitHub Action with a severity gate.

It started as my graduation project and I am continuing it in the open. I would most
like feedback on the engine — especially where it produces false positives you would
not tolerate.

https://github.com/KimJeju/cpguard
```

**첫 댓글 (기술 설명 — 게시 직후 직접 달 것):**
```
Some detail on the engine, since that is the part worth criticising.

Each file becomes a language-neutral IR, so a normalizer per language is all a new
language needs; the taint rules are YAML (sources, sinks, sanitizers, propagators) and
are shared across languages where the shape matches. The CPG is deliberately small —
AST, CFG, def-use, call — not a general-purpose graph database, because the only
queries I run are reachability ones.

Interprocedural analysis is function summaries rather than full IFDS: for each rule I
compute, per function, whether a parameter reaches a sink and whether the return value
is tainted, then propagate at call sites until fixpoint. It over-approximates on
purpose — an unknown callee passes taint through, container writes taint the whole
container — because for a security tool a missed flow costs more than a false one, and
the workbench plus LLM triage is where the noise gets filtered.

Known limits: no path sensitivity (a validated flow still reports), string keys are
tracked only for literal indexes, and reflection/dynamic dispatch is invisible. Those
are the top three sources of false positives in the benchmark run.
```

> HN 팁: 오전(미 동부 기준) 게시, 첫 댓글에 "how it works" 간단히. 과장 금지, 정직하게.

---

## X / Twitter (스레드)

1/ 오픈소스 SAST 를 만들었습니다 — **CPGuard**.
정규식 패턴 대신 **코드 속성 그래프(CPG)** 로 Source→Sink taint 흐름을 추적해 취약점을 찾습니다.
🔗 github.com/KimJeju/cpguard

2/ 핵심은 두 가지:
① CPG + 프로시저간 taint 분석 → 파일을 넘나드는 흐름 추적
② LLM 트리아지(Claude/Gemini/GPT) → 오탐 재검증
패턴 매칭 SAST 의 오탐 지옥을 줄이는 게 목표.

3/ Ghidra/Fortify 결의 **3분할 감사 작업대** — 코드 위에 흐름을 그려주고, 사람이 최종 판정.
완전 오프라인(파이썬·인터넷·관리자 권한 X). CI 는 GitHub Action + SARIF.
[스크린샷 첨부: docs/img/workbench.png]

4/ 실제 26k 파일 / 2.3GB 프로젝트로 검증 — 약 5분에 4,900여 건.
졸업작품에서 시작해 오픈소스로 잇는 중입니다. 피드백 환영 🙏

> 이미지: docs/img/workbench.png (히어로), docs/img/charts.png

---

## GeekNews (news.hada.io) / disquiet — 한국어

**제목:** CPGuard – CPG 기반 taint 분석 + LLM 트리아지 오픈소스 SAST

**본문:**
```
정규식/패턴 위주 SAST 의 오탐 한계를 넘어보려고 만든 오픈소스 정적 보안 분석 도구입니다.

- tree-sitter 파싱 → 언어중립 IR → CPG(AST·CFG·def-use·call) → 프로시저간 taint(함수 요약)
  로 사용자 입력(source)이 위험 지점(sink)까지 흐르는지 파일 넘나들며 추적합니다.
- LLM(Claude/Gemini/GPT) 트리아지로 각 이슈의 도달 가능성을 재검증해 오탐을 줄입니다.
- Ghidra/Fortify 결의 3분할 감사 작업대: 코드 뷰어에 Source→Sink 흐름을 강조하고,
  인스펙터에서 사람이 판정·메모합니다.
- 완전 오프라인(파이썬·인터넷·관리자 권한 불필요, 단일 설치본). 에어갭 환경 대응.
- SARIF·GitHub Action 으로 CI 연동. 언어: JS/TS·PHP·Python·Java·Kotlin·Go·Ruby·C/C++·Swift·C#.
- 라벨링 정답지 8개 언어 76,866건(채점 기준)으로 측정. 자바 0.826 · C++ 0.79 · 파이썬 0.717 · Go 0.57 · C 0.52 · JS 0.43 · Ruby 0.42 · TS 0.41 · PHP 0.369 · C# 0.245 — 편차도, C·C++ 수치의 한계도 그대로 공개합니다. 측정 스크립트와 제외 기준도 공개.
- 실제 26,049 파일 / 2.3GB 프로젝트로 검증(약 5분에 4,857건).

졸업작품에서 시작해 오픈소스로 이어가고 있습니다. 엔진·오탐률 피드백 특히 환영합니다.

https://github.com/KimJeju/cpguard
```

---

## Reddit (r/netsec, r/opensource, r/devops)

> r/netsec 는 자기홍보 규칙이 엄격 — "how it works" 중심의 기술 글로. 아래는 r/opensource·r/devops 용.

**Title:** `CPGuard: open-source SAST with CPG taint analysis + LLM triage (offline, SARIF/CI)`

**Body:** (Show HN 본문 재사용 + 스크린샷 링크)

---

## LinkedIn (전문가/보안 대상)

```
정적 보안 분석(SAST) 도구 CPGuard 를 오픈소스로 공개했습니다.

패턴 매칭 위주 도구의 오탐 한계를 넘고자, 코드 속성 그래프(CPG) 기반 프로시저간 taint 분석에
LLM 트리아지를 결합했습니다. Source→Sink 흐름을 코드 위에 시각화하는 감사 작업대,
완전 오프라인 동작, SARIF/GitHub Action CI 연동을 갖췄습니다.

실제 26k 파일 / 2.3GB 규모 프로젝트로 검증했습니다. 보안·DevSecOps 하시는 분들의 피드백을 기다립니다.

#SAST #AppSec #DevSecOps #OpenSource #보안
https://github.com/KimJeju/cpguard
```

---

## 채널 체크리스트

- [ ] GitHub repo: About·topics·소셜 프리뷰 이미지 설정(Settings → Social preview 에 workbench.png)
- [ ] Show HN (Hacker News) — 오전 게시, 첫 댓글에 기술 설명
- [ ] GeekNews(news.hada.io) 제출
- [ ] disquiet.io / 커리어리 포스트
- [ ] X/Twitter 스레드 + 워크벤치 스크린샷
- [ ] LinkedIn 포스트
- [ ] Reddit: r/opensource, r/devops (r/netsec 은 규칙 확인 후)
- [ ] dev.to 런치 블로그(선택) — "How I built a CPG-based SAST"
- [ ] awesome-static-analysis 목록에 PR(선택)
- [ ] OWASP Slack / 로컬 보안 커뮤니티 공유

## 주의

- 과장 금지: "상용 대비 오탐 X%↓" 같은 수치는 **벤치마크(OWASP Benchmark) 공개 후** 사용.
- 아직 초기(졸업작품 출발) 임을 밝히면 오히려 신뢰↑. 피드백 요청형 톤이 반응 좋음.
- 각 커뮤니티 자기홍보 규칙 준수(특히 r/netsec, HN).
