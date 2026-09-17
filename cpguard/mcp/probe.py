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


#: 라우트 선언. (프레임워크 verb 그룹) — 메서드·경로·핸들러 참조가 한 줄에 있는 형태.
#: gin: r.POST("/p", handler)  ·  express: app.post("/p", handler)  ·  .Handle("GET","/p",h)
_ROUTE = re.compile(
    r"""\.(?P<verb>get|post|put|delete|patch|any|all|head|options|handle|handlefunc)\s*\(\s*"""
    r"""(?:['"](?P<m>GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"]\s*,\s*)?"""   # .Handle("GET", ...)
    r"""['"](?P<path>[^'"]+)['"]""",
    re.IGNORECASE)

#: 함수 정의 시작. 위로 올라가며 sink 를 감싼 핸들러 이름을 찾는다.
_FUNCDEF = re.compile(
    r"""(?:func\s+(?:\([^)]*\)\s*)?(?P<go>\w+)\s*\(|"""          # Go: func (r T) Name( / func Name(
    r"""function\s+(?P<js>\w+)\s*\(|"""                          # JS: function name(
    r"""(?:const|let|var)\s+(?P<jsc>\w+)\s*=\s*(?:async\s*)?\(|"""  # JS: const name = (
    r"""def\s+(?P<py>\w+)\s*\()""")


def _enclosing_fn(lines: list[str], sink_line: int) -> str | None:
    """sink 줄을 감싼 가장 가까운 함수 이름(위로 탐색). 없으면 None."""
    for i in range(min(sink_line, len(lines)) - 1, -1, -1):
        if m := _FUNCDEF.search(lines[i]):
            return m.group("go") or m.group("js") or m.group("jsc") or m.group("py")
    return None


def _route_hint(f: Finding) -> tuple[str | None, str] | None:
    """finding 의 파일에서 핸들러에 걸린 라우트를 최선값으로 뽑는다. (메서드, 경로) 또는 None.

    라우트 등록이 핸들러와 **같은 파일**에 있고, 그 등록 줄에 핸들러 이름이 나올 때만
    인정한다. 다른 파일에 있거나 이름이 안 맞으면 None — 에이전트가 확인하게 둔다.
    익명 핸들러(`app.post("/p", (req,res)=>{...})`)는 라우트 리터럴이 sink 를 감싼
    범위 안에 있으면 그 경로를 쓴다.
    """
    try:
        text = open(f.file, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    lines = text.splitlines()
    sink_line = f.sink.loc.start_line

    fn = _enclosing_fn(lines, sink_line)
    verb_method = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
                   "patch": "PATCH", "head": "HEAD", "options": "OPTIONS"}

    best_inline = None
    for i, line in enumerate(lines, 1):
        m = _ROUTE.search(line)
        if not m:
            continue
        method = (m.group("m") or verb_method.get(m.group("verb").lower()) or "").upper() or None
        path = m.group("path")
        # 이름 매칭: 등록 줄에 핸들러 이름이 있으면 확정에 가깝다
        if fn and re.search(r"\b" + re.escape(fn) + r"\b", line):
            return method, path
        # 익명 핸들러: 라우트 선언이 sink 를 감싸는 위치(위쪽 가까이)면 후보로
        if i <= sink_line and (best_inline is None or i > best_inline[0]):
            best_inline = (i, method, path)
    if best_inline and fn is None:      # 이름으로 못 잡았고 감싸는 라우트가 있으면 그걸로
        return best_inline[1], best_inline[2]
    return None


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

    # 라우트를 같은 파일에서 뽑았으면 경로·메서드가 확정에 가깝다.
    route = _route_hint(f)
    path = None
    confidence = "hint" if (method is not None or param is not None) else "unknown"
    if route is not None:
        rmethod, path = route
        method = rmethod or method     # 라우트 verb 가 접근자 추정보다 낫다
        confidence = "resolved"        # 경로까지 나왔다 — 그래도 에이전트가 최종 확인
    return {
        "method": method,
        "location": location,          # query | form | header | path | cookie | body
        "param": param,
        "path": path,                  # 라우트 경로(같은 파일서 뽑힘). null 이면 에이전트가 확인
        "confidence": confidence,      # resolved | hint | unknown
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
