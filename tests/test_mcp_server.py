"""MCP 서버 0단계 — 걷는 뼈대.

SDK(`mcp`) 없이도 도는 부분(순수 `health`)과, SDK 가 있을 때만 도는 부분(서버 구성·
도구 등록)을 나눈다. SDK 미설치 환경에서 전체 스위트가 깨지지 않게 한다 — MCP 는
선택 의존성이다.
"""
import importlib.util

import pytest

from cpguard.mcp import server

_HAS_MCP = importlib.util.find_spec("mcp") is not None
_needs_mcp = pytest.mark.skipif(not _HAS_MCP, reason="mcp SDK 미설치 (pip install cpguard[mcp])")


def test_health_shape():
    """코어 연결 확인 — 분석 없이 규칙·언어 수를 센다."""
    h = server.health()
    assert h["server"] == "cpguard"
    assert h["status"] == "ok"
    assert h["taint_rules"] > 0 and h["pattern_rules"] > 0
    assert "go" in h["languages"] and "java" in h["languages"]


@_needs_mcp
def test_server_registers_health_tool():
    """SDK 가 있으면 서버가 구성되고 health 도구가 등록돼 있다."""
    srv = server.build_server()
    names = {t.name for t in srv._tool_manager.list_tools()}
    assert "cpguard.health" in names


# ── 2단계: 읽기 쪽 도구 (scan_file · finding.list · finding.evidence · explain) ──

from cpguard.mcp import tools  # noqa: E402

_GO_VULN = """package handler

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Handle(c *gin.Context) {
	data := c.Query("id")
	exec.Command("sh", "-c", "echo "+data)   // 명령 주입
	_ = http.StatusOK
}
"""


def _scanned(tmp_path):
    f = tmp_path / "h.go"
    f.write_text(_GO_VULN, encoding="utf-8")
    store = tools.FindingStore()
    res = tools.scan_file(store, str(f))
    return store, res


def test_scan_file_finds_and_registers(tmp_path):
    store, res = _scanned(tmp_path)
    assert res["total"] >= 1
    ids = [x["id"] for x in res["findings"]]
    assert all(store.get(i) is not None for i in ids)       # id 로 다시 집힌다
    assert all("steps" not in x for x in res["findings"])   # 목록엔 흐름 없음(토큰 예산)


def test_scan_file_missing_path():
    store = tools.FindingStore()
    assert tools.scan_file(store, "no/such/file.go")["error"] == "not_found"


def test_finding_list_filters(tmp_path):
    store, res = _scanned(tmp_path)
    fid = res["findings"][0]["id"]
    rule = store.get(fid).rule_id
    # rule 부분일치로 좁혀도 그 건이 남고, 없는 규칙으로 거르면 0
    assert tools.finding_list(store, rule=rule)["total"] >= 1
    assert tools.finding_list(store, rule="does.not.exist")["total"] == 0


def test_finding_evidence_has_path(tmp_path):
    store, res = _scanned(tmp_path)
    fid = res["findings"][0]["id"]
    ev = tools.finding_evidence(store, fid)
    assert ev["source"]["kind"] == "source" and ev["sink"]["kind"] == "sink"
    assert len(ev["path"]) >= 2
    assert tools.finding_evidence(store, "nope")["error"] == "unknown_finding"


def test_explain_by_finding_and_rule(tmp_path):
    store, res = _scanned(tmp_path)
    fid = res["findings"][0]["id"]
    by_find = tools.explain(store, finding_id=fid)
    assert by_find["remediation"] and by_find["safe_example"]
    by_rule = tools.explain(store, rule_id="go.sqli")
    assert by_rule["title"] and by_rule["safe_example"]
    assert tools.explain(store)["error"] == "need_rule_or_finding"


@_needs_mcp
def test_all_mvp_tools_registered():
    names = {t.name for t in server.build_server()._tool_manager.list_tools()}
    assert {"scan_file", "finding.list", "finding.evidence", "explain",
            "cpguard.health"} <= names


# ── 3단계: 실증 루프 (probe.get · validation.submit) ──

from cpguard.mcp import probe  # noqa: E402

# sink 유형별 최소 재현 — probe 가 맞는 오라클을 내는지(idiom 방식). (본문, 기대 오라클)
_PROBE_CASES = {
    "cmdi": ("""package h
import ("os/exec"; "github.com/gin-gonic/gin")
func H(c *gin.Context){ d := c.Query("id"); exec.Command("sh","-c","echo "+d) }
""", "time_delay"),
    "ssrf": ("""package h
import ("net/http"; "github.com/gin-gonic/gin")
func H(c *gin.Context){ u := c.PostForm("url"); http.Get(u) }
""", "oast_callback"),
}


def _one_probe(tmp_path, src):
    f = tmp_path / "h.go"
    f.write_text(src, encoding="utf-8")
    store = tools.FindingStore()
    res = tools.scan_file(store, str(f))
    fid = res["findings"][0]["id"]
    return store, fid, tools.probe_get(store, fid)


def test_probe_oracle_matches_sink_type(tmp_path):
    for _name, (src, want_oracle) in _PROBE_CASES.items():
        _store, _fid, p = _one_probe(tmp_path, src)
        assert p["oracle"]["type"] == want_oracle, (_name, p["oracle"])
        assert p["payload"]                                   # 페이로드가 있다
        assert p["flow"][0] and p["flow"][-1]                 # source·sink 코드


def test_probe_extracts_entry(tmp_path):
    _store, _fid, p = _one_probe(tmp_path, _PROBE_CASES["cmdi"][0])
    e = p["entry"]
    assert e["method"] == "GET" and e["location"] == "query" and e["param"] == "id"
    assert e["confidence"] == "hint"
    assert e["path"] is None                                  # 라우트는 에이전트 몫


def test_probe_unknown_finding(tmp_path):
    store = tools.FindingStore()
    assert tools.probe_get(store, "nope")["error"] == "unknown_finding"


# ── validation.submit 판정 행렬 ──

def _finding(tmp_path, src):
    f = tmp_path / "h.go"; f.write_text(src, encoding="utf-8")
    store = tools.FindingStore()
    fid = tools.scan_file(store, str(f))["findings"][0]["id"]
    return store, fid


def test_verdict_confirmed_on_oracle_hit(tmp_path):
    store, fid = _finding(tmp_path, _PROBE_CASES["cmdi"][0])
    v = tools.validation_submit(store, fid, {"elapsed_ms": 5200})
    assert v["verdict"] == "CONFIRMED"


def test_verdict_not_reproduced_is_not_false_positive(tmp_path):
    """핵심 경계 — 발사했으나 안 터진 것과 정적으로 안전한 것은 다르다."""
    store, fid = _finding(tmp_path, _PROBE_CASES["cmdi"][0])
    v = tools.validation_submit(store, fid, {"elapsed_ms": 40})
    assert v["verdict"] == "NOT_REPRODUCED"
    assert v["verdict"] != "FALSE_POSITIVE"


def test_verdict_blocked_reason_preserved(tmp_path):
    store, fid = _finding(tmp_path, _PROBE_CASES["cmdi"][0])
    v = tools.validation_submit(store, fid, {"blocked": "REQUIRES_AUTH"})
    assert v["verdict"] == "NOT_VALIDATED" and v["blocked_reason"] == "REQUIRES_AUTH"


def test_verdict_likely_on_partial(tmp_path):
    store, fid = _finding(tmp_path, _PROBE_CASES["cmdi"][0])
    v = tools.validation_submit(store, fid, {"elapsed_ms": 30, "error_signature": "sh: syntax"})
    assert v["verdict"] == "LIKELY"


def test_verdict_false_positive_when_static_safe(tmp_path):
    store, fid = _finding(tmp_path, _PROBE_CASES["cmdi"][0])
    v = tools.validation_submit(store, fid, {"static_safe": True})
    assert v["verdict"] == "FALSE_POSITIVE"


@_needs_mcp
def test_stage3_tools_registered():
    names = {t.name for t in server.build_server()._tool_manager.list_tools()}
    assert {"probe.get", "validation.submit"} <= names


# ── MVP 이후: 비동기 전체 감사 (scan_start · scan_status) ──

import time as _time  # noqa: E402

from cpguard.mcp import jobs as _jobs  # noqa: E402


def _wait(runner, job_id, timeout=30.0):
    end = _time.time() + timeout
    while _time.time() < end:
        st = runner.status(job_id)
        if st.get("status") in ("completed", "failed"):
            return st
        _time.sleep(0.05)
    return runner.status(job_id)


def test_scan_start_runs_and_populates_store(tmp_path):
    (tmp_path / "a.go").write_text(_GO_VULN, encoding="utf-8")
    (tmp_path / "safe.go").write_text(
        "package h\nfunc F() { _ = 1 }\n", encoding="utf-8")
    store = tools.FindingStore()
    runner = _jobs.JobRunner(store)

    started = runner.start(str(tmp_path))
    assert started["job_id"].startswith("scan_")

    st = _wait(runner, started["job_id"])
    assert st["status"] == "completed", st
    assert st["found"] >= 1 and st["counts"]        # 숫자만
    assert "findings" not in st                     # 목록을 붓지 않는다(토큰 예산)

    # 완료 후 finding.list 가 그 결과를 이어받는다
    assert tools.finding_list(store)["total"] == st["found"]


def test_scan_status_unknown_job():
    runner = _jobs.JobRunner(tools.FindingStore())
    assert runner.status("scan_nope")["error"] == "unknown_job"


def test_scan_start_missing_root():
    runner = _jobs.JobRunner(tools.FindingStore())
    assert runner.start("no/such/dir")["error"] == "not_found"


@_needs_mcp
def test_async_tools_registered():
    names = {t.name for t in server.build_server()._tool_manager.list_tools()}
    assert {"scan_start", "scan_status"} <= names


# ── MVP 이후: verify (고친 뒤 전후 대조) ──

_GO_FIXED = """package handler

import (
	"net/http"
	"os/exec"

	"github.com/gin-gonic/gin"
)

func Handle(c *gin.Context) {
	data := c.Query("id")
	_ = data
	exec.Command("echo", "safe")   // 오염값을 안 넘김 — 고쳐짐
	_ = http.StatusOK
}
"""


def test_verify_reports_closed_after_fix(tmp_path):
    f = tmp_path / "h.go"
    f.write_text(_GO_VULN, encoding="utf-8")
    store = tools.FindingStore()
    scan = tools.scan_file(store, str(f))          # baseline 잡힘 (취약 1건)
    assert scan["total"] >= 1

    f.write_text(_GO_FIXED, encoding="utf-8")       # 에이전트가 고침
    v = tools.verify(store, str(f))
    assert v["closed"] >= 1
    assert v["remaining"] == []
    assert v["verdict"] == "all_closed"


def test_verify_still_vulnerable_when_unfixed(tmp_path):
    f = tmp_path / "h.go"
    f.write_text(_GO_VULN, encoding="utf-8")
    store = tools.FindingStore()
    tools.scan_file(store, str(f))
    v = tools.verify(store, str(f))                 # 안 고치고 재검증
    assert v["closed"] == 0
    assert len(v["remaining"]) >= 1
    assert v["verdict"] == "still_vulnerable"


def test_verify_no_baseline(tmp_path):
    f = tmp_path / "h.go"
    f.write_text(_GO_VULN, encoding="utf-8")
    store = tools.FindingStore()
    v = tools.verify(store, str(f))                 # 스캔 이력 없이 바로 verify
    assert v["baseline"] == "none"                  # '전부 새로 생김'이라 하지 않는다


@_needs_mcp
def test_verify_tool_registered():
    names = {t.name for t in server.build_server()._tool_manager.list_tools()}
    assert "verify" in names


# ── 라우트 힌트 강화 ──

def test_probe_resolves_route_from_same_file(tmp_path):
    src = """package main
import ("os/exec"; "github.com/gin-gonic/gin")
func vuln(c *gin.Context) { d := c.Query("id"); exec.Command("sh","-c","echo "+d) }
func main() { r := gin.Default(); r.POST("/run", vuln); r.Run() }
"""
    f = tmp_path / "m.go"; f.write_text(src, encoding="utf-8")
    store = tools.FindingStore()
    fid = tools.scan_file(store, str(f))["findings"][0]["id"]
    e = tools.probe_get(store, fid)["entry"]
    assert e["path"] == "/run"
    assert e["method"] == "POST"            # 라우트 verb 가 우선
    assert e["confidence"] == "resolved"


def test_probe_route_unknown_when_absent(tmp_path):
    # 라우트 등록이 없으면 경로 null, confidence 는 resolved 가 아니다
    f = tmp_path / "h.go"; f.write_text(_GO_VULN, encoding="utf-8")
    store = tools.FindingStore()
    fid = tools.scan_file(store, str(f))["findings"][0]["id"]
    e = tools.probe_get(store, fid)["entry"]
    assert e["path"] is None
    assert e["confidence"] != "resolved"
