<p align="center">
  <img src="assets/icon.png" width="128" alt="CPGuard"/>
</p>
<h1 align="center">CPGuard</h1>

<p align="center">
  <b>망분리 환경에서 소스코드부터 진단 산출물까지 한 번에</b><br/>
  <sub>CPG 기반 Taint 분석 · LLM 트리아지 · 진단결과보고서와 분석목록표 자동 생성 — 외부로 아무것도 내보내지 않는 데스크톱 도구</sub>
</p>

<p align="center">
  <a href="README.md">English</a> · <b>한국어</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Platform-Windows%20%C2%B7%20macOS%20%C2%B7%20Linux-0078D6" alt="Windows / macOS / Linux">
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0">
  <img src="https://img.shields.io/badge/Django-5.2-092E20?logo=django&logoColor=white" alt="Django 5.2">
  <img src="https://img.shields.io/badge/languages-11-4da3ff" alt="11개 언어">
  <img src="https://img.shields.io/badge/taint%20rules-78-4da3ff" alt="taint 규칙 78개">
  <img src="https://img.shields.io/badge/tests-220%20passing-2e7d32" alt="tests passing">
  <img src="https://img.shields.io/badge/OWASP%20Benchmark-N%3D1572%20·%20F1%200.595-2e7d32" alt="OWASP Benchmark">
  <img src="https://img.shields.io/badge/LLM-Claude%20%C2%B7%20GPT%20%C2%B7%20Gemini-8b5cf6" alt="LLM">
</p>

<p align="center">
  <img src="docs/img/architecture.svg" width="820" alt="CPGuard 분석 파이프라인"/>
</p>

> **CPGuard** = **CPG**(Code Property Graph, 코드 속성 그래프) + **Guard** — 패턴 목록이 아니라 코드 속성 그래프로 코드를 지킨다. 로고가 3개의 연결된 노드인 이유도 이 그래프다.

패턴 매칭 중심 SAST 의 오탐 한계를 넘기 위해 —
**tree-sitter 파싱 → 언어중립 IR → CPG(AST·CFG·def-use·call) → 프로시저간 taint(함수 요약) → LLM 트리아지**
로 정밀 탐지하고, 3분할 검토 화면에서 사람이 최종 판정한다.

<p align="center">
  <img src="docs/img/workbench.png" width="900" alt="CPGuard 취약점 검토 — 코드 뷰어 위의 Source→Sink taint 흐름과 인스펙터"/>
  <br/>
  <sub>취약점 검토 — 코드 뷰어 위에 <b>Source→Sink</b> taint 흐름을 강조하고, 인스펙터에서 규칙·CWE·흐름 단계·판정을 한눈에.</sub>
</p>

---

## ✨ 주요 기능

**탐지 두 축**
- **데이터 흐름(taint)** — **11개 언어**: JavaScript · TypeScript · PHP · Python · Java · Kotlin · Go · Ruby · C/C++ · Swift · C# (확장자 27종, **규칙 77개**).
  SQL 주입(CWE-89) · 명령 주입(78) · 코드 주입(94) · XSS(79) · 경로 조작(22) · 파일 포함(98) · SSRF(918) · 오픈 리다이렉트(601) · 안전하지 않은 역직렬화(502) · 버퍼 오버플로(120) · 포맷 스트링(134) · LDAP(90)/XPath(643) 주입 · WebView XSS · Intent 리다이렉션(926) · 라이브러리 주입(114).
- **패턴(단일 지점)** — 전 언어. 하드코딩 비밀정보·벤더키(798) · 개인정보(PII) · TLS 검증 비활성(295) · 취약 해시/암호(327) · 예측 가능 난수(338) · 쿠키 플래그(1004) · 디버그 코드.

**취약점 검토 화면**
- 3분할: 좌 이슈 탐색기(목록·표·소스 트리) / 중앙 코드 뷰어 / 우 인스펙터.
- 문법 하이라이팅 · 커맨드 팔레트(`Ctrl+P`) · 우클릭 컨텍스트 메뉴 · 여백 마커.
- **데이터 흐름 시각화** — Source→Sink 단계 그래프와 코드 뷰어가 동기화된다.
- **AI 분석 패널** — 선택한 이슈의 규칙·흐름·주변 코드를 자동으로 붙여 질의.
- 판정(취약 확정 / 오탐 / 조치완료 / 보류)과 감사자 의견, 판정별 행 색상, 감사 상태 필터, 스캔 간 신규/해결 비교.

**규모: 담당자 1명, 프로젝트 수백 개**
- **다건 업로드** — zip 여러 개를 한 번에 선택하거나, 프로젝트 zip 들을 담은 zip 하나를 올리면 각각 프로젝트가 된다.
- **배치 진행** — FIFO 워커가 프로젝트를 순차 진단하고 프로젝트별 상태를 보여준다.
- **프로젝트 포트폴리오** (`/projects/`) — 전 프로젝트의 최신 스캔을 한 표에서 검색·정렬·필터.
- **대량 산출물 배부** — 프로젝트를 골라 각 프로젝트의 PDF 보고서와 xlsx 를 담은 ZIP 하나로 내려받아 개발자에게 전달.

**LLM 트리아지**
- Claude · ChatGPT(OpenAI) · Gemini. 도달 가능성 재검증과 설명, 프로바이더·모델 선택 가능. Gemini 무료 티어로 바로 시험해 볼 수 있다.

**산출물**
- **진단 결과 보고서(PDF)** — 표지 · 문서 개정 이력 · 목차 · 대상 범위/진단 방법 · 위험도 차트 · 진단 항목 · 취약점별 상세 카드(대상 · 설명 · 데이터 흐름 단계 · 영향 · 조치 방안 · 안전 예시 · CWE 참고) · 종합 의견 · 위험도 판정 기준 부록 · 회차별 진단 이력 표.
- 조치 가이드(PDF) · SARIF 2.1.0 · CSV · 14컬럼 분석목록표(xlsx).
- 보고서 메타(작성자 · 수행 기관 · 발주처 · 담당자 · 기간 · 버전)는 설정 화면에서 입력한다.

**UX·배포**
- 플랫한 모던 IDE 디자인, 테마 4종(다크 / 라이트 / VS Code / Ghidra).
- **한국어 ⇄ English 토글** — UI 뿐 아니라 서버 생성물까지: 룰 메시지 · PDF 보고서 · xlsx · CSV · SARIF.
- **오프라인·클린 머신 설치** — 파이썬·인터넷·관리자 권한 없이 단일 exe(PyInstaller + Inno Setup).
- 네이티브 데스크톱 창(WebView2, 부재 시 브라우저 폴백) 또는 브라우저 대시보드.

---

## 🖥 화면

| 대시보드 | 취약점 탐색 (차트·필터·페이지네이션) |
|:---:|:---:|
| ![대시보드](docs/img/dashboard.png) | ![취약점 탐색](docs/img/charts.png) |
| 상태 타일 · 위험도 분포 · 상위 규칙 | 위험도 도넛 · 상위 규칙/CWE 막대 · 대량 탐지 탐색기 |

<p align="center">
  <img src="docs/img/reports.png" width="780" alt="리포트·내보내기"/>
  <br/>
  <sub>리포트·내보내기 — 스캔별 진단 보고서·조치 가이드 PDF · SARIF · CSV · 분석목록표(xlsx)</sub>
</p>

> 취약점 검토 화면(코드 뷰어 + Source→Sink 흐름 + 인스펙터)은 위쪽 히어로 이미지 참조.

---

## 📦 다운로드 / 설치

### 설치본 — Windows (권장 · 파이썬 불필요)

[Releases](https://github.com/KimJeju/cpguard/releases) 에서 `CPGuard-Setup-0.1.5.exe` 를 받아 실행합니다.
사용자 영역 설치라 관리자 권한이 필요 없고, WebView2 런타임이 없으면 자동 설치합니다.

직접 빌드하려면:

```powershell
powershell -ExecutionPolicy Bypass -File packaging/build.ps1
```

무설치 이동식으로도 쓸 수 있습니다 — `dist/CPGuard` 폴더를 통째로 복사해 `CPGuard.exe` 실행.

### 소스에서 — Windows · macOS · Linux

```bash
pip install .
cpguard --help
```

분석 엔진·웹 UI·모든 산출물 포맷은 순수 파이썬이라 세 플랫폼에서 동일하게 동작합니다.
설치본과 네이티브 데스크톱 창(WebView2)만 Windows 전용입니다. PDF 보고서의 한글 출력에는
한글 폰트가 필요한데, Windows·macOS 는 기본 탑재이고 Linux 는 `fonts-nanum` 을 설치하거나
`CPGUARD_PDF_FONT` 환경변수로 원하는 TrueType 폰트를 지정하면 됩니다.

## 🚀 사용법

```bash
# CLI 스캔 (SARIF·분석목록표 산출)
cpguard scan ./project --sarif out.sarif --xlsx out.xlsx

# LLM 트리아지로 오탐 재검증
cpguard scan ./project --triage --provider gemini

# 웹 대시보드 (브라우저)
cpguard serve

# 네이티브 데스크톱 창
cpguard app
```

대시보드에서: zip 업로드 → 진행 화면(단계 체크리스트·구동 로그) → 검토·판정 →
⚙️ 설정에 LLM 키를 넣으면 AI 분석·트리아지가 활성화됩니다.

## 🔁 CI/CD (GitHub Actions)

PR·푸시마다 자동 스캔 → SARIF 를 **GitHub Code Scanning** 에 올려 신규 취약점을 코드/PR 에
인라인 표시. 등급 게이트로 빌드 실패도 가능.

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
          fail-on: 'high'      # high 이상 탐지 시 빌드 실패 (none=게이트 안 함)
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: '${{ steps.cpguard.outputs.sarif }}' }
```

CLI 로도 게이트 가능: `cpguard scan . --sarif out.sarif --fail-on high`
(해당 등급 이상 탐지 시 종료코드 1). 이 저장소의 [`.github/workflows/cpguard.yml`](.github/workflows/cpguard.yml) 이 실동작 예시.

---

## 🧱 아키텍처

```
tree-sitter → 언어중립 IR → CPG(AST·CFG·def-use·call) → 프로시저간 taint(함수 요약)
                                                              ↘ LLM 트리아지 → 검토 화면 / 리포트
전 언어 패턴 축(비밀정보·PII·설정 점검) ──────────────────────↗
```

- **건전한 과대근사** — 분기 양쪽 병합, 요약 고정점(재귀·상호재귀), 미상 함수는 오염 통과.
- **무결성 보고** — "0건"이 안전인지 못 읽은 건지 구분(파싱 실패·크기 초과·구문오류 기록·표시).
- **읽기 전용·근거 수집** 기조: 도구가 조용히 취약점을 숨기지 않고, 최종 판정은 사람이.
- 언어 추가는 포크가 아니라 표 하나 — 정규화기가 각 문법의 노드를 공통 IR 로 옮기므로 CPG·taint 엔진은 그대로다.

스택: Python 3.11+ · tree-sitter(11개 언어) · Django(SSR) · reportlab(PDF) ·
openpyxl(xlsx) · SARIF 2.1.0 · LLM SDK(anthropic/openai/google-genai) · pytest.

## 📊 정확도

**OWASP Benchmark v1.2**(Java, 취약/안전 쌍이 라벨된 정답지)의 데이터 흐름 6개 유형,
**표본 1,572건** 기준 측정 결과입니다.

| 재현율 | 정밀도 | F1 | 오탐률 | 점수 |
|---:|---:|---:|---:|---:|
| 56.0% | 63.5% | 0.595 | 35.1% | **0.210** |

점수 = 재현율 − 오탐률 (OWASP Benchmark 공식 지표, 무작위 추측 = 0.000).
설정 점검 성격의 유형(`weakrand`·`crypto`·`hash`·`securecookie`·`trustbound`, 1,168건)은
데이터 흐름 문제가 아니므로 공짜 점수로 넣지 않고 지표에서 제외했습니다.

**오탐의 원인을 측정했습니다.** 안전 케이스 753건 중 **347건(46%)** 이
`if ((7 * 42) - num > 200) bar = "상수"; else bar = param;` 처럼 컴파일 시점에 결과가
정해지는 조건으로 취약 경로를 죽입니다. CPGuard 는 설계상 경로 민감도가 없어 양쪽 분기를
모두 가능하다고 보므로 이런 케이스를 오탐으로 냅니다. **상수 전파(constant propagation)가
오탐률을 낮출 가장 큰 단일 지렛대**이며, 다음 엔진 과제로 잡았습니다.

실제 앱(DVWA, PHP) 기준 보조 측정도 함께 공개합니다. 전체 방법론·유형별 표·한계는
[`bench/README.md`](bench/README.md) 참조.

## 📈 대규모 코드베이스

20~30GB 소스나 5만 건 이상 탐지 같은 극단 규모의 최적화 전략(싱크 사전 필터링,
증분·요약 캐시, Finding DB 테이블화, 집계·가상 스크롤, 트리아지 클러스터링 등)은
[`docs/large-scale.md`](docs/large-scale.md) 참조.

## 🗺️ 로드맵

- [x] taint 코어 · 패턴 엔진 · LLM 트리아지 · 취약점 검토 화면
- [x] PDF 진단 보고서·조치 가이드 · 오프라인 설치본
- [x] Finding DB 테이블화 + 서버측 페이지네이션 · 가상 스크롤(대량 탐지)
- [x] 싱크 사전 필터링 · 멀티프로세스 · 파싱/요약 캐시 · 트리아지 클러스터링
- [x] CI/CD 통합 — GitHub Action · SARIF → Code Scanning · 등급 게이트
- [x] 정확도 벤치마크 공개 — OWASP Benchmark v1.2, 표본 1,572건, F1 0.595 ([상세](bench/README.md))
- [x] 11개 언어 — Java · Kotlin · Go · Ruby · C/C++ · Swift · C# 추가
- [x] 다건 배치 진단 · 프로젝트 포트폴리오 · 대량 산출물 배부
- [ ] 상수 전파(경로 민감도) 도입으로 오탐률 감소
- [ ] sanitizer 인식 강화 · 프레임워크 인지 진입점(Spring·JPA)

## 📄 라이선스

[Apache License 2.0](LICENSE). 상업적 이용을 포함해 자유롭게 사용·수정·재배포할 수 있으며,
저작권 고지와 라이선스 전문을 유지하면 됩니다. 명시적 특허 사용 허락 조항을 포함합니다.
