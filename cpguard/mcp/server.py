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

    from . import jobs, tools

    server = MCPServer(SERVER_NAME)
    store = tools.FindingStore()      # 세션 상태 — 이 서버 프로세스 한 대화 분량
    runner = jobs.JobRunner(store)    # 비동기 스캔 작업 — 같은 store 를 채운다

    @server.tool(name="cpguard.health",
                 description="CPGuard 서버 상태와 규칙·언어 수를 반환한다(분석 안 함).")
    def _health() -> dict:
        return health()

    @server.tool(name="scan_file",
                 description="소스 파일 하나를 빠르게 진단하고 요약(흐름 단계 없음)을 "
                             "반환한다. 찾은 건은 finding.evidence·explain 이 쓰도록 id 로 저장된다.")
    def _scan_file(path: str) -> dict:
        return tools.scan_file(store, path)

    @server.tool(name="finding.list",
                 description="저장된 취약점을 심각도·규칙·파일 필터와 페이지로 나열한다"
                             "(기본 20건, 요약만). severity 는 목록, rule·file 은 부분일치.")
    def _finding_list(severity: list[str] | None = None, rule: str | None = None,
                      file: str | None = None, limit: int = 20, offset: int = 0) -> dict:
        return tools.finding_list(store, severity, rule, file, limit, offset)

    @server.tool(name="finding.evidence",
                 description="취약점 하나의 source→sink 데이터 흐름 경로를 반환한다"
                             "(왜 취약으로 판단했는지의 근거).")
    def _finding_evidence(finding_id: str) -> dict:
        return tools.finding_evidence(store, finding_id)

    @server.tool(name="explain",
                 description="규칙의 설명·CWE·조치 권고·안전 예시를 반환한다(LLM 호출 없음). "
                             "finding_id 또는 rule_id 로 조회. lang='en' 으로 영문.")
    def _explain(rule_id: str | None = None, finding_id: str | None = None,
                 lang: str = "ko") -> dict:
        return tools.explain(store, rule_id, finding_id, lang)

    @server.tool(name="scan_start",
                 description="리포/디렉터리 전체를 비동기로 감사한다. 즉시 job_id 를 "
                             "반환하고 백그라운드로 스캔한다(분 단위). 진행·결과는 "
                             "scan_status 로 확인. 찾은 건은 finding.list 로 이어받는다.")
    def _scan_start(root: str, jobs: int = 1) -> dict:
        return runner.start(root, jobs)

    @server.tool(name="scan_status",
                 description="scan_start 작업의 상태를 숫자만 반환한다(queued·running·"
                             "completed·failed, 진행률·심각도별 건수). 완료되면 finding.list "
                             "로 결과를 가져간다 — findings 를 통째로 붓지 않는다.")
    def _scan_status(job_id: str) -> dict:
        return runner.status(job_id)

    @server.tool(name="probe.get",
                 description="취약점 하나를 동적 실증용 탐침으로 반환한다 — 진입점(메서드·"
                             "파라미터)·페이로드·오라클(무엇을 관찰하면 실증인지)·흐름. 서버는 "
                             "요청을 발사하지 않는다. 에이전트가 자기 web 도구로 쏘고 결과를 "
                             "validation.submit 으로 되돌린다.")
    def _probe_get(finding_id: str) -> dict:
        return tools.probe_get(store, finding_id)

    @server.tool(name="validation.submit",
                 description="에이전트가 탐침을 발사하고 관찰한 결과(observed)를 오라클과 "
                             "대조해 판정한다: CONFIRMED · LIKELY · NOT_REPRODUCED · "
                             "FALSE_POSITIVE(+검증불가 사유). observed 키는 elapsed_ms·oast_hit·"
                             "body_marker·file_leak·redirect_external·error_signature·blocked 등.")
    def _validation_submit(finding_id: str, observed: dict) -> dict:
        return tools.validation_submit(store, finding_id, observed)

    return server


def main() -> None:
    """stdio 로 서버를 띄운다. 진입점 `cpguard-mcp`."""
    build_server().run()  # 기본 전송 = stdio


if __name__ == "__main__":
    main()
