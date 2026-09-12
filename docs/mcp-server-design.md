# CPGuard MCP 서버 — 설계

작성 2026-09-12. 상태: 설계 승인 대기.

## 무엇을, 왜

AI 코딩 에이전트(Claude Code·Cursor 등)가 CPGuard를 **붙여 쓰는** MCP 서버.
핵심 사용 흐름은 두 가지다.

1. **코드 검사** — 에이전트가 작업 중인 코드를 즉시 진단하고 흐름을 본다.
2. **취약점 실증(고객 니즈)** — SAST가 찾은 취약점이 실제로 동작하는지 동적으로
   확인한다.

두 번째가 이 설계의 중심이고, 접근은 **B(조준자)**다. CPGuard는 DAST 엔진이 되지
않는다 — `source → sink → 관찰점`을 아는 우리의 해자를 탐침으로 내주고, 실제 발사는
에이전트가 자기 web 도구로 한다. 근거는 아래 "경계"와 "왜 B인가"에 적는다.

## 왜 B인가 (A·C를 버린 이유)

- **해자는 방아쇠가 아니라 조준이다.** HTTP 요청 발사는 흔한 일이고, 이 환경의
  에이전트는 이미 그 도구(web-hunter·webapp-pentester·`web:*`)를 쥐고 있다. CPGuard에
  HTTP 클라이언트·프레임워크별 라우팅 해석기를 넣으면 더 못한 DAST 사본이 된다.
- **제품 정체성·안전.** CPGuard는 망분리·외부 무전송 데스크톱 도구다. 코어가 소켓을
  열면 모든 배포가 그 책임을 진다. 동적 발사는 인가된 대상에 사람/에이전트가 건
  별도 행위로 둔다 — 인가가 올바른 층에 산다.
- **C(정적 재판정)는 니즈를 못 맞춘다.** 고객은 "실증"을 원하는데 C는 여전히
  "우리 생각엔 닿는다"다.

## 경계 (깨면 안 되는 것)

1. **코드를 실행하지 않는다.** 읽고 파싱만 한다. 규칙/테스트에 등장하는 `system()`·
   `exec.Command` 는 전부 탐지 대상 문자열이지 실행 대상이 아니다.
2. **파일을 쓰지 않는다.** 유일한 예외는 SARIF 내보내기이고, 그것도 클라이언트가
   출력 경로를 명시했을 때만. 소스 편집·패치 도구는 두지 않는다 — 호스트가 이미
   편집기다.
3. **스캔 루트를 벗어나지 않는다.** 루트 밖 경로는 거절한다.
4. **동적 발사를 하지 않는다.** `probe.get` 으로 탐침을 주고, 에이전트가 본 결과를
   `validation.submit` 으로 돌려받아 판정할 뿐이다.
5. **전송은 stdio 하나.** 네트워크를 열지 않는다. 로컬 IDE 에이전트 전용.
6. **선택 의존성.** `pip install "cpguard[mcp]"`. CLI만 쓰는 사용자에게 `mcp` SDK를
   지우지 않는다.

## 우리 것 / 호스트 것

코드 인텔리전스 대부분은 호스트 에이전트가 파일시스템·LSP·grep으로 이미 더 잘한다.
우리는 **분석이 필요한 것만** 낸다.

| 우리만 줄 수 있는 것 (도구로 낸다) | 호스트가 이미 하는 것 (안 만든다) |
|---|---|
| finding.list / finding.get / finding.evidence | source.tree / source.read |
| flow.path | code.search / symbol.search |
| explain (CWE·조치 권고·안전 예시) | 파일 편집·패치 |
| callers (콜그래프 정방향) | |
| scan_file / scan_start / scan_status (비동기) | |
| probe.get (실증 탐침 + 오라클) | |
| validation.submit (관찰결과 받아 판정) | |
| verify (고친 뒤 전후 대조) | |

## 코드 기준 현실 (과장 금지)

구현 전에 실제 가능 여부를 코드로 확인했다. 스펙은 이 경계 위에서만 약속한다.

- **`Finding.steps` 가 파일 넘는 source→sink 경로 + 단계별 코드 스니펫을 이미 들고
  있다.** → `finding.evidence`·`flow.path` 는 성형만 하면 된다. 가장 강한 카드.
- **콜그래프는 정방향만 있다**(누가 부르나=역방향 없음). → `callers` 는 역엣지
  구축이 필요한 신규 작업. MVP 밖.
- **심볼 DB·지역변수 인덱스가 없다.** → `symbol.references` 류는 내지 않는다(호스트 몫).
- **`scan_path` 는 무상태**다(scan_id·incremental·프로젝트 DB 없음). 프로젝트 이력은
  Django 쪽에 있으나 IDE용이라 안 붙인다. → MVP는 무상태로 간다.
- **런타임 트레이스·IAST 계측이 없다.** → "정적 경로 == 동적 실행 경로" 상관은
  **불가**. 정직한 검증 모델은 아래 "오라클 일치"다.

## 검증 모델 — 오라클 일치 (IAST 아님)

구동 앱을 계측해 실제 실행 경로를 뽑는 IAST는 우리에게 없다. 그래서 검증은
**오라클 일치**로 한다.

CPGuard는 sink 종류를 아니까 **무엇을 관찰해야 실증인지**를 정확히 지정한다.
블랙박스 DAST가 추측하는 바로 그 지점이다.

| sink 유형 | 오라클(이게 나타나면 실증) |
|---|---|
| 명령 실행 | 시간지연(`; sleep 5`) 또는 OAST 콜백 토큰 |
| SQL | 불리언 분기 차이 · DB 에러 시그니처 · 시간지연 |
| XSS | 응답에 반사된 고유 마커 |
| SSRF | 우리 서버가 아니라 OAST 엔드포인트로의 콜백 |
| 경로 조작 | 범위 밖 파일 내용 · 특정 에러 |

에이전트가 탐침을 발사하고 관찰한 것을 돌려주면, CPGuard가 오라클과 대조해 판정한다.
**이것을 IAST·런타임 상관이라고 부르지 않는다** — 오라클 일치다.

## 판정 4분류 + 검증불가 사유

```
CONFIRMED        오라클 관찰됨 — 실증 완료
LIKELY           정적 근거 강하고 오라클 부분 일치(완전 재현 부족)
NOT_REPRODUCED   발사했으나 오라클 안 나타남
FALSE_POSITIVE   정적으로 봐도 안전(가드 존재 등)
```

**`NOT_REPRODUCED ≠ FALSE_POSITIVE`.** 재현 못 한 것과 취약점이 아닌 것은 다르다.
검증을 못 한 이유도 별도로 기록한다.

```
REQUIRES_AUTH        인증 뒤라 도달 못 함
UNSAFE_ENVIRONMENT   운영·파괴 위험으로 발사 보류
VALIDATION_BLOCKED   WAF·레이트리밋 등으로 막힘
REQUIRES_USER_ACTION 사람 조작이 있어야 도달
```

## 데이터 흐름 (B 루프)

```
finding.evidence  →  probe.get(finding)          우리: 탐침 + 오라클
        ↓
   [에이전트가 자기 web 도구로 발사]              호스트: 실제 HTTP
        ↓
validation.submit(finding, 관찰결과)             에이전트가 본 것을 되돌려줌
        ↓
   오라클과 대조 → verdict                        우리: 상관 = 오라클 일치
```

### probe.get 반환(형태)

```json
{
  "finding_id": "...",
  "entry":   { "method": "POST", "path": "/api/search", "confidence": "hint" },
  "param":   "q",
  "payload": "; sleep 5 #",
  "oracle":  { "type": "time_delay", "expect": "응답 5초 이상 지연" },
  "flow":    ["q (source)", "data", "exec.Command (sink)"]
}
```

`entry` 는 source 근처 라우트 선언에서 **최선값으로** 뽑는다(gin `r.POST("/x", h)`,
express `app.post('/x', ...)`). 못 뽑으면 `confidence: "unknown"` 으로 표시하고
에이전트에게 라우트 확인을 맡긴다 — 보장이 아니다.

### validation.submit 입력(형태)

```json
{
  "finding_id": "...",
  "observed": { "status": 200, "elapsed_ms": 5120, "body_marker": null,
                "oast_hit": false, "error_signature": null }
}
```

CPGuard는 `observed` 를 probe의 `oracle` 과 대조해 위 4분류 중 하나를 낸다.

## 아키텍처

```
cpguard/mcp/
  server.py     도구 등록 · stdio 수명주기 · main()
  tools.py      도구 구현 (코어 호출 + 결과 성형)
  jobs.py       비동기 스캔 작업 (scan_start/status)
  probe.py      finding → 탐침 + 오라클 (sink 유형별 오라클 테이블)
  render.py     Finding → 토큰 예산에 맞춘 표현 (페이지·필터)
```

코어(`scanner`·`taint`·`report`)를 **위에서 호출만** 한다. 코어는 MCP를 모른다 —
Django 대시보드가 SARIF 계약으로만 붙은 것과 같은 규약.

진입점: `pyproject.toml` `[project.scripts]` 에 `cpguard-mcp = "cpguard.mcp.server:main"`.

## 토큰 예산 (설계의 진짜 제약)

리포 하나에 이슈 수백~수천이 나온다. 통째로 컨텍스트에 부으면 에이전트가 그 자리에서
쓸모없어진다.

- `scan_status` 는 **숫자만**(건수·심각도 분포).
- `finding.list` 는 **기본 20건 페이지 + 심각도/규칙/파일 필터**.
- 흐름 단계(`evidence`·`flow.path`)는 **요청한 finding 에만** 붙인다.
- `explain` 의 안전 예시는 요청 시에만.

## 코어에서 빼낼 것 하나

조치 권고·안전 예시 테이블이 `report/pdf.py:119` 안에 묶여 있다. PDF 작성기에 갇혀
있어 `explain` 이 못 쓴다. `cpguard/report/remediation.py` 로 옮기고 pdf는 거기서
가져다 쓴다. 이 작업에 필요한 만큼만 손대고, 기존 `tests/test_remediation_map.py` 가
회귀를 잡는다.

## MVP (6개) — "SAST→실증 루프" 한 바퀴

```
scan_file            빠른 파일 검사
finding.list         필터·페이지로 이슈 목록
finding.evidence     source→sink 경로(= Finding.steps)
explain              규칙·CWE·조치 권고·안전 예시
probe.get            실증 탐침 + 오라클
validation.submit    관찰결과 받아 4분류 판정
```

### MVP 이후

- `scan_start` / `scan_status` — 리포 전체 비동기 감사.
- `flow.path` — evidence와 겹치나 finding 없이 경로만 필요할 때.
- `callers` — 콜그래프 역엣지 구축 후.
- `verify` — 고친 뒤 전후 대조(직전 스캔 결과를 경로당 한 벌 보관).
- 프로젝트 이력(`project.*`·scan_id) — 필요해지면 경량 저장소. 지금은 Django와 중복.

## 테스트 전략

- 도구별 계약 테스트: 입력 → 반환 형태(JSON 스키마) 고정.
- `probe.py` sink-유형별 오라클 매핑 테스트(기존 idiom 테스트와 같은 방식: 최소 재현
  코드에 규칙 적용 → 탐침이 맞는 오라클을 내는가).
- 경계 테스트: 루트 밖 경로 거절, 파일 미기록, 코드 미실행.
- 판정 테스트: `observed` × `oracle` 조합 → 4분류가 맞게 갈리는가(특히
  `NOT_REPRODUCED` 가 `FALSE_POSITIVE` 로 뭉개지지 않는가).

## 미해결·위험

- **라우트 매핑**(핸들러→실제 엔드포인트)은 최선값 힌트일 뿐. 못 뽑는 프레임워크가
  많을 것이다. 에이전트가 닫는다는 전제.
- **오라클 일치의 한계**: 응답만 보는 블랙박스보다는 강하지만 IAST는 아니다.
  "실제 실행 경로 확인"이라고 보고하지 않는다 — "예측한 관찰이 나타났다"로 적는다.
- 고객이 **CPGuard 단독 턴키 실증**(에이전트 없이 버튼 하나)을 원하면 이 설계(B)로는
  안 된다 — A로 다시 봐야 한다. 현재 전제는 "IDE 에이전트가 항상 건너편에 있다"이다.
