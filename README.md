# CPGuard

Code Property Graph 기반 Taint 분석 + LLM 트리아지를 결합한 오픈소스 정적 보안 분석(SAST) 도구.

패턴 매칭 중심 상용 SAST의 오탐 한계를 넘기 위해, tree-sitter 파싱 → 언어중립 IR → CPG(AST·CFG·def-use·call) → 프로시저간 taint(함수 요약 기반) → LLM 트리아지로 정밀 탐지를 목표로 한다.

## 상태

SP1/SP4/SP6 구현 완료 · JS/TS/PHP/Python 어댑터 동작. 설계 명세와 졸업과제 문서는
`C:\Users\MyPC\Desktop\KUNHWI\6.졸업과제`.

## 구성 (분해)

| # | 서브프로젝트 | 졸업 제출 |
|---|---|---|
| SP1 | JS/TS/PHP/Python taint 코어 (파싱→IR→CPG→taint→SARIF) | ✅ |
| SP3 | 패턴 엔진 (비밀정보·개인정보·설정 위생) | ✅ |
| SP4 | LLM 트리아지 (오탐 제거·도달성 설명) | ✅ |
| SP6 | Django SSR 감사 작업대 (시연) | ✅ |
| SP2 | Java 어댑터 | 향후 |
| SP5 | 패키징·CI 통합 | ✅ |

## 스택

Python 3.11+ · tree-sitter(js/ts/php/python) · Django(SSR) · SARIF 2.1.0 ·
openpyxl(분석목록표) · LLM API(Claude/OpenAI/Gemini) · pytest

## 탐지 두 축

- **데이터 흐름(taint)** — JS/TS/PHP/Python. command injection(CWE-78), code injection(CWE-94),
  XSS(CWE-79), path traversal(CWE-22), SSRF(CWE-918), SQL injection(CWE-89),
  file inclusion(CWE-98, PHP), open redirect(CWE-601)
- **패턴(단일 지점)** — 전 언어. 하드코딩 비밀정보(CWE-798)·벤더키, 개인정보(PII),
  TLS 검증 비활성(CWE-295), 취약 해시/암호(CWE-327), 예측 가능 난수(CWE-338),
  쿠키 플래그(CWE-1004), 디버그 코드(CWE-489)

## 감사 작업대 (Workbench)

Fortify/Ghidra 결의 3분할 데스크톱 작업대 — 좌 이슈 탐색기 / 중앙 코드+분석 패널 / 우 인스펙터.
패널 폭·표시·필터는 브라우저에 기억한다.

- **문법 하이라이팅** — 코드 뷰어가 키워드·문자열·주석·숫자·함수를 색으로 구분.
  라이브러리 없이 정규식 토크나이저, js/ts/php/py 키워드셋+주석문법 분기.
  (한계: 줄 단위라 여러 줄 걸친 주석·템플릿 문자열은 첫 줄만)
- **커맨드 팔레트** — `Ctrl+P`(또는 `Ctrl+Shift+F`)로 전역 이동 오버레이. 규칙·파일·CWE 검색,
  이슈/파일 그룹 표시, `↑↓`/`Enter`/`Esc`.
- **우클릭 컨텍스트 메뉴** — 이슈 목록·표에서 조사·코드 열기·경로/ID 복사·확정/오탐/보류/감사 해제·AI 설명.
- **여백 마커 hover 툴팁** — 코드 여백의 다른 이슈 마커에 위험도·규칙·CWE·OWASP·신뢰도·위치.
- **데이터 흐름 시각화** — Source→Sink 단계 그래프와 코드 뷰어 동기화(단계 클릭 시 해당 줄로 점프).
- **AI 분석 패널** — 현재 이슈의 규칙·흐름·주변 코드를 자동으로 붙여 설명/악용 가능성/조치 질의.
- **표 보기 · 감사 상태 · 스캔 간 신규/해결 비교 · SARIF/CSV/분석목록표 내보내기.**
