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
