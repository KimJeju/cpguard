# CPGuard 홍보 키트

릴리스 v0.1.2 기준. 아래 초안은 그대로 복붙하거나 다듬어 쓰면 됩니다.
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
- **CI 연동** — GitHub Action + SARIF → Code Scanning. `fail-on` 게이트.
- **언어** — JavaScript · TypeScript · PHP · Python.
- 오픈소스(졸업작품에서 출발).

---

## Show HN (Hacker News)

**Title:**
`Show HN: CPGuard – Open-source SAST with CPG taint analysis + LLM triage, runs offline`

**Body:**
```
I built CPGuard, an open-source static analysis tool for finding security bugs in source code.

Most affordable SAST is regex/pattern based and drowns you in false positives. CPGuard instead
builds a code property graph (AST + CFG + def-use + call graph) and runs interprocedural taint
analysis with function summaries, so it traces user input from source to a dangerous sink across
files. On top of that it can use an LLM (Claude/Gemini/GPT) to triage each finding for
reachability, which cuts false positives further.

It ships a Ghidra/Fortify-style 3-pane audit workbench: issue explorer, a code viewer that
highlights the Source→Sink flow inline, and an inspector where a human confirms the verdict and
writes notes. Everything runs fully offline (no Python/admin needed, single installer); only the
optional LLM triage calls a cloud API.

Languages: JS/TS/PHP/Python. Exports SARIF (GitHub Code Scanning), plus PDF report / xlsx.
There's a GitHub Action for CI with a severity gate. I tested it end-to-end on a real 26k-file /
2.3GB project (~4,900 findings in ~5 min).

It started as my graduation project and I'm continuing it as open source. Feedback very welcome —
especially on the detection engine and false-positive rate.

https://github.com/KimJeju/cpguard
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
- SARIF·GitHub Action 으로 CI 연동. 언어: JS/TS/PHP/Python.
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
