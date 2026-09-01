# CPGuard

Code Property Graph 기반 Taint 분석 + LLM 트리아지를 결합한 오픈소스 정적 보안 분석(SAST) 도구.

패턴 매칭 중심 상용 SAST의 오탐 한계를 넘기 위해, tree-sitter 파싱 → 언어중립 IR → CPG(AST·CFG·def-use·call) → 프로시저간 taint(함수 요약 기반) → LLM 트리아지로 정밀 탐지를 목표로 한다.

## 상태

설계 완료, SP1 구현 착수 전. 설계 명세와 졸업과제 문서는
`C:\Users\MyPC\Desktop\KUNHWI\6.졸업과제`.

## 구성 (분해)

| # | 서브프로젝트 | 졸업 제출 |
|---|---|---|
| SP1 | JS/TS taint 코어 (파싱→IR→CPG→taint→SARIF) | ✅ |
| SP4 | LLM 트리아지 (오탐 제거·도달성 설명) | ✅ |
| SP6 | Django SSR 대시보드 (시연) | ✅ |
| SP2 | Java 어댑터 | 향후 |
| SP3 | 고속 패턴 엔진 | 향후 |
| SP5 | 패키징·CI 통합 | 향후 |

## 스택

Python 3.11+ · tree-sitter(js/ts) · Django(SSR) · SARIF 2.1.0 · LLM API · pytest

## 출하 규칙 6종

command injection(CWE-78), code injection(CWE-94), XSS(CWE-79),
path traversal(CWE-22), SSRF(CWE-918), SQL injection(CWE-89)
