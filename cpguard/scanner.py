"""프로젝트 디렉터리 스캔 오케스트레이션.

파일 워크 -> 전체 파싱 -> 공용 함수 레지스트리/요약 -> 파일별 분석 -> Finding 목록.
CLI 와 웹 대시보드가 공통으로 쓰는 진입점이다.

프로시저간 분석을 파일 경계 너머로 확장하려면 모든 파일을 먼저 파싱해 두어야 한다.
한 파일에서 정의된 함수를 다른 파일이 호출하는 경우를 다루기 위함이다.
"""
from __future__ import annotations

from pathlib import Path

from . import ir
from .cpg.callgraph import collect_functions
from .parse import loader, normalize
from .report.finding import Finding
from .taint import engine
from .taint.spec import Rule, load_rules

# 스캔에서 제외할 디렉터리 (의존성·빌드 산출물)
DEFAULT_EXCLUDES = {
    "node_modules", ".git", "dist", "build", "out", "coverage",
    ".next", ".nuxt", "vendor", "__pycache__", ".venv",
}

MAX_FILE_BYTES = 2_000_000  # 2MB 초과 파일은 건너뜀 (미니파이 번들 등)


def iter_source_files(root: str | Path, excludes: set[str] | None = None):
    root = Path(root)
    excludes = DEFAULT_EXCLUDES if excludes is None else excludes
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower() not in loader.SUPPORTED_EXTENSIONS:
            continue
        if any(part in excludes for part in p.parts):
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield p


def parse_file(path: str | Path) -> tuple[ir.Module, bytes, str]:
    """파일 하나를 파싱해 (IR 모듈, 원본 바이트, 언어이름) 반환."""
    path = Path(path)
    lang = loader.language_name_for(path)
    src = path.read_bytes()
    tree = loader.parse_source(src, language=lang)
    return normalize.normalize(tree, file=str(path), language=lang), src, lang


def scan_file(path: str | Path, rules: list[Rule] | None = None) -> list[Finding]:
    """단일 파일 스캔(그 파일 안에서만 프로시저간 분석)."""
    path = Path(path)
    module, src, lang = parse_file(path)
    if rules is None:
        rules = load_rules(language=lang)
    return engine.analyze(module, src, [r for r in rules if lang in r.languages])


def scan_path(root: str | Path, rules: list[Rule] | None = None,
              excludes: set[str] | None = None) -> tuple[list[Finding], int]:
    """디렉터리(또는 단일 파일) 스캔. 반환: (findings, 스캔한 파일 수).

    성능 메모: 요약 계산은 (규칙 수 × 함수 수 × 파라미터 수 × 반복) 에 비례한다.
    대형 프로젝트에서 느려지면 규칙별 소스/싱크 사전 필터링이 다음 최적화 지점이다.
    """
    root = Path(root)
    if rules is None:
        rules = load_rules()

    files = [root] if root.is_file() else list(iter_source_files(root, excludes))

    # 1) 전부 파싱 (한 파일 실패가 전체 스캔을 죽이지 않게 한다)
    parsed: list[tuple[Path, ir.Module, bytes, str]] = []
    for f in files:
        try:
            module, src, lang = parse_file(f)
        except Exception:
            continue
        parsed.append((f, module, src, lang))

    if not parsed:
        return [], 0

    # 2) 파일 경계를 넘는 공용 함수 레지스트리와 규칙별 요약
    registry = collect_functions([(m, src, str(p)) for p, m, src, _ in parsed])
    summaries_by_rule = {r.id: engine.compute_summaries(registry, r) for r in rules}

    # 3) 파일별 분석
    findings: list[Finding] = []
    for _, module, src, lang in parsed:
        applicable = [r for r in rules if lang in r.languages]
        if not applicable:
            continue
        findings.extend(engine.analyze(
            module, src, applicable,
            registry=registry, summaries_by_rule=summaries_by_rule,
        ))
    return findings, len(parsed)
