"""stdio MCP 서버 · 도구 등록 · main().

0단계(걷는 뼈대): 분석 로직 없이 배선만 증명한다. `cpguard.health` 하나만 등록해
에이전트가 붙어 도구 목록을 받고 호출되는지 확인한다. 실제 도구는 이후 단계에서 tools
/probe/jobs 모듈로 들어온다.

MCP SDK(`mcp`)는 선택 의존성이다 — `pip install "cpguard[mcp]"`. SDK 없이도 이 모듈의
순수 함수(`health`)는 import·테스트되도록, SDK 의존은 서버를 **만들 때만** 건다.

SDK 버전 주의: mcp 2.x 에서 `FastMCP` 가 `MCPServer`(`mcp.server.mcpserver`)로 개명됐다.
도구 데코레이터·`run()`·`list_tools()` 시그니처는 그대로다. 1.x 를 쓰면 import 가
`mcp.server.fastmcp.FastMCP` 로 달라진다 — pyproject 는 `mcp>=1.2` 라 2.x 가 설치된다.
"""
from __future__ import annotations

#: 서버가 보고하는 기능 수준. 도구가 늘면 여기 한 줄씩 는다(0단계는 health 뿐).
SERVER_NAME = "cpguard"


def health() -> dict:
    """서버가 살아 있고 코어를 import 할 수 있음을 증명하는 고정 형태 응답.

    분석을 돌리지 않는다 — 규칙·언어 수를 세어 코어 연결만 확인한다. 에이전트가
    "CPGuard 붙었나"를 물을 때의 답이기도 하다.
    """
    from cpguard.patterns import load_pattern_rules
    from cpguard.taint.spec import load_rules

    rules = load_rules(user_dir=False)
    patterns = load_pattern_rules()
    languages = sorted({lang for r in rules for lang in r.languages})
    return {
        "server": SERVER_NAME,
        "status": "ok",
        "taint_rules": len(rules),
        "pattern_rules": len(patterns),
        "languages": languages,
    }


def build_server():
    """FastMCP 인스턴스를 구성해 돌려준다. SDK 가 있어야 한다.

    도구 등록을 한곳에 모아 두어, 테스트가 '무엇이 등록됐나'를 이 함수 결과로 물을 수
    있게 한다. stdio 실행은 main() 이 맡는다.
    """
    from mcp.server.mcpserver import MCPServer

    server = MCPServer(SERVER_NAME)

    @server.tool(name="cpguard.health",
                 description="CPGuard 서버 상태와 규칙·언어 수를 반환한다(분석 안 함).")
    def _health() -> dict:
        return health()

    return server


def main() -> None:
    """stdio 로 서버를 띄운다. 진입점 `cpguard-mcp`."""
    build_server().run()  # 기본 전송 = stdio


if __name__ == "__main__":
    main()
