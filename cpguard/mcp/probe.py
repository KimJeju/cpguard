"""실증 탐침 + 오라클, 그리고 관찰결과 판정.

접근 B: CPGuard 는 DAST 엔진이 아니다. finding 의 source→sink 를 아는 것으로
**무엇을 어디에 넣으면 어느 지점이 터지고, 무엇을 관찰해야 실증인가**(오라클)를 낸다.
실제 발사는 호스트 에이전트가 자기 web 도구로 한다. 발사 결과(observed)를 되돌려받아
오라클과 대조해 판정한다.

검증 모델은 **오라클 일치**다 — 런타임 트레이스(IAST)가 아니다. 계측이 없으므로
"실제 실행 경로 확인"이 아니라 "예측한 관찰이 나타났다"까지만 말한다.

순수 모듈 — MCP SDK 비의존.
"""
from __future__ import annotations

import re

from cpguard.report.finding import Finding
from cpguard.report.remediation import rule_key

#: 고유 반사 마커. XSS 처럼 "응답에 그대로 되나"를 보는 오라클이 쓴다. 무작위가 아니라
#: 결정적이어야 에이전트가 응답에서 찾을 문자열을 미리 안다.
MARKER = "cpg-PROBE-7f3a"

#: 시간지연 오라클의 임계(ms). payload 의 sleep 초와 맞춘다.
DELAY_SECONDS = 5
DELAY_MS = DELAY_SECONDS * 1000

#: sink 유형(rule_key 결과) -> (payload, 오라클). 오라클이 이 도구의 핵심이다 —
#: sink 를 아니까 블랙박스가 추측하는 '무엇을 관찰해야 하나'를 정확히 지정한다.
_ORACLE: dict[str, dict] = {
    "command-injection": {
        "payload": f"; sleep {DELAY_SECONDS} #",
        "oracle": {"type": "time_delay",
                   "expect": f"응답이 {DELAY_SECONDS}초 이상 지연되면 명령이 실행된 것"}},
    "sqli": {
        "payload": f"' OR SLEEP({DELAY_SECONDS})-- -",
        "oracle": {"type": "time_delay",
                   "expect": f"응답이 {DELAY_SECONDS}초 이상 지연되거나 DB 에러가 나면 주입"}},
    "ssrf": {
        "payload": "http://<OAST-TOKEN>/",
        "oracle": {"type": "oast_callback",
                   "expect": "<OAST-TOKEN> 엔드포인트로 서버발 콜백이 오면 SSRF. "
                             "우리 서버가 아니라 에이전트의 OAST 리스너로 확인"}},
    "xss": {
        "payload": f"<{MARKER}>",
        "oracle": {"type": "reflected_marker",
                   "expect": f"응답 본문에 '<{MARKER}>' 가 이스케이프 없이 그대로 반사되면 XSS"}},
    "path-traversal": {
        "payload": "../../../../etc/passwd",
        "oracle": {"type": "file_content",
                   "expect": "응답에 /etc/passwd 내용(예: 'root:')이 보이면 경로 조작"}},
    "file-inclusion": {
        "payload": "../../../../etc/passwd",
        "oracle": {"type": "file_content",
                   "expect": "포함된 파일 내용이 응답에 드러나면 파일 삽입"}},
    "open-redirect": {
        "payload": "//evil.example/",
        "oracle": {"type": "redirect_location",
                   "expect": "Location 헤더가 외부 도메인(evil.example)으로 향하면 오픈 리다이렉트"}},
}

#: 자동 오라클을 세우기 어려운 유형 — 에이전트/사람이 직접 판단하도록 남긴다.
#: 없는 것을 있는 척하지 않는다.
_MANUAL_ORACLE = {"type": "manual",
                  "expect": "자동 오라클 없음 — 흐름을 보고 수동으로 실증 판단 필요"}

#: 요청 접근자 -> (HTTP 메서드, 값이 들어가는 자리). 확신하는 것만 넣고 나머지는 unknown.
_ACCESSOR = {
    # gin / net-http
    "Query": ("GET", "query"), "GetQuery": ("GET", "query"), "DefaultQuery": ("GET", "query"),
    "PostForm": ("POST", "form"), "DefaultPostForm": ("POST", "form"),
    "Param": ("GET", "path"), "GetHeader": ("GET", "header"), "Cookie": ("GET", "cookie"),
    "FormValue": ("GET", "query"), "PostFormValue": ("POST", "form"),
    "Body": ("POST", "body"), "GetRawData": ("POST", "body"),
    # express / node (req.query / req.body / req.params)
    "query": ("GET", "query"), "body": ("POST", "body"), "params": ("GET", "path"),
    # java servlet
    "getParameter": ("GET", "query"), "getHeader": ("GET", "header"),
    # flask / django
    "args": ("GET", "query"), "form": ("POST", "form"),
}


def _entry(f: Finding) -> dict:
    """source 에서 HTTP 진입점을 최선값으로 추출한다. 못 뽑으면 confidence=unknown.

    라우트 경로(/api/x)는 finding 에 없다 — 에이전트가 구동 앱에서 확인해야 한다.
    여기서 주는 것은 메서드·값 위치·파라미터 이름까지다.
    """
    src = f.source.code or ""
    accessor = src.rsplit(".", 1)[-1]           # "c.Query" -> "Query"
    method, location = _ACCESSOR.get(accessor, (None, None))

    # 파라미터 이름: 접근자 호출의 문자열 리터럴 인자. source 다음 스텝들에 원문이 있다.
    param = None
    pat = re.compile(re.escape(accessor) + r"""\(\s*['"]([^'"]+)['"]""")
    for s in f.steps:
        if m := pat.search(s.code or ""):
            param = m.group(1)
            break

    known = method is not None or param is not None
    return {
        "method": method,
        "location": location,          # query | form | header | path | cookie | body
        "param": param,
        "path": None,                  # 라우트 경로 — 에이전트가 확인
        "confidence": "hint" if known else "unknown",
    }


def build_probe(f: Finding, finding_id: str) -> dict:
    """finding 하나를 실증 탐침으로. 발사는 에이전트가, 판정은 judge() 가 한다."""
    vuln = rule_key(f.rule_id)
    spec = _ORACLE.get(vuln)
    payload = spec["payload"] if spec else None
    oracle = spec["oracle"] if spec else _MANUAL_ORACLE
    return {
        "id": finding_id,
        "vuln_type": vuln or f.rule_id,
        "entry": _entry(f),
        "payload": payload,
        "oracle": oracle,
        "flow": [s.code for s in f.steps],
        "note": ("실제 요청은 에이전트가 자기 web 도구로 발사한다. 라우트 경로가 unknown 이면 "
                 "구동 앱에서 확인할 것. 관찰결과는 validation.submit 으로 되돌려 판정한다."),
    }


#: 검증 불가 사유 — 재현 실패(NOT_REPRODUCED)와 구분해 보존한다.
_BLOCKED = {"REQUIRES_AUTH", "UNSAFE_ENVIRONMENT", "VALIDATION_BLOCKED", "REQUIRES_USER_ACTION"}


def judge(f: Finding, observed: dict) -> dict:
    """오라클 × 관찰결과 → 4분류(+검증불가 사유).

    observed 는 에이전트가 발사 후 본 것: {elapsed_ms, oast_hit, body_marker,
    file_leak, redirect_external, error_signature, status, blocked}.

    NOT_REPRODUCED != FALSE_POSITIVE 를 지킨다 — 발사했으나 안 터진 것과, 정적으로도
    안전한 것은 다르다. blocked 사유가 오면 그대로 실어 재현 실패로 뭉개지 않는다.
    """
    vuln = rule_key(f.rule_id)
    spec = _ORACLE.get(vuln)
    otype = spec["oracle"]["type"] if spec else "manual"

    if (b := observed.get("blocked")):
        reason = b if b in _BLOCKED else "VALIDATION_BLOCKED"
        return _v("NOT_VALIDATED", otype, reason=reason,
                  why="검증을 수행하지 못했다 — 재현 실패가 아니다")

    if observed.get("static_safe"):
        return _v("FALSE_POSITIVE", otype, why="정적으로도 안전(가드 존재 등)으로 보고됨")

    hit, partial, why = _match(otype, observed)
    if hit:
        return _v("CONFIRMED", otype, why=why)
    if partial:
        return _v("LIKELY", otype, why=why)
    return _v("NOT_REPRODUCED", otype,
              why="발사했으나 오라클이 나타나지 않았다(취약점이 아니라는 뜻은 아니다)")


def _match(otype: str, o: dict) -> tuple[bool, bool, str]:
    """(확정, 부분일치, 사유). 오라클 유형별로 관찰결과를 읽는다."""
    if otype == "time_delay":
        if (o.get("elapsed_ms") or 0) >= DELAY_MS:
            return True, False, f"응답 지연 {o['elapsed_ms']}ms ≥ {DELAY_MS}ms"
        if o.get("error_signature"):
            return False, True, "지연은 없지만 DB/실행 에러 시그니처가 관찰됨"
        return False, False, ""
    if otype == "oast_callback":
        return bool(o.get("oast_hit")), False, "OAST 콜백 수신" if o.get("oast_hit") else ""
    if otype == "reflected_marker":
        return bool(o.get("body_marker")), False, "마커가 응답에 반사됨" if o.get("body_marker") else ""
    if otype == "file_content":
        return bool(o.get("file_leak")), False, "파일 내용 노출 관찰" if o.get("file_leak") else ""
    if otype == "redirect_location":
        return bool(o.get("redirect_external")), False, "외부 도메인으로 리다이렉트" if o.get("redirect_external") else ""
    # manual: 자동 판정 불가 — 에이전트 판단에 맡긴다
    return False, bool(o.get("agent_confirmed")), "자동 오라클 없음"


def _v(verdict: str, oracle_type: str, why: str, reason: str | None = None) -> dict:
    out = {"verdict": verdict, "oracle_type": oracle_type, "reason": why}
    if reason:
        out["blocked_reason"] = reason
    return out
