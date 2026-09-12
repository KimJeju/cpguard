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
