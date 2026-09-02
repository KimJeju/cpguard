"""프로젝트 디렉터리 스캔 오케스트레이션.

파일 워크 -> 파싱 -> IR -> taint -> Finding 목록.
CLI 와 웹 대시보드가 공통으로 쓰는 진입점이다.
"""
from __future__ import annotations

from pathlib import Path

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


def scan_file(path: str | Path, rules: list[Rule] | None = None) -> list[Finding]:
    path = Path(path)
    lang = loader.language_name_for(path)
    if rules is None:
        rules = load_rules(language=lang)
    src = path.read_bytes()
    tree = loader.parse_source(src, language=lang)
    module = normalize.normalize(tree, file=str(path), language=lang)
    return engine.analyze(module, src, [r for r in rules if lang in r.languages])


def scan_path(root: str | Path, rules: list[Rule] | None = None,
              excludes: set[str] | None = None) -> tuple[list[Finding], int]:
    """디렉터리(또는 단일 파일) 스캔. 반환: (findings, 스캔한 파일 수)."""
    root = Path(root)
    if rules is None:
        rules = load_rules()

    if root.is_file():
        return scan_file(root, rules), 1

    findings: list[Finding] = []
    count = 0
    for f in iter_source_files(root, excludes):
        count += 1
        try:
            findings.extend(scan_file(f, rules))
        except Exception:
            # 한 파일 파싱 실패가 전체 스캔을 죽이지 않게 한다
            continue
    return findings, count
