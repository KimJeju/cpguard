"""프로젝트 디렉터리 스캔 오케스트레이션.

파일 워크 -> 전체 파싱 -> 공용 함수 레지스트리/요약 -> 파일별 분석 -> Finding 목록.
CLI 와 웹 대시보드가 공통으로 쓰는 진입점이다.

프로시저간 분석을 파일 경계 너머로 확장하려면 모든 파일을 먼저 파싱해 두어야 한다.
한 파일에서 정의된 함수를 다른 파일이 호출하는 경우를 다루기 위함이다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
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


@dataclass
class ScanReport:
    """스캔 무결성 보고.

    "취약점 0건"이 정말 안전하다는 뜻인지, 아니면 파일을 못 읽어서인지 구분해야 한다.
    조용히 건너뛴 파일을 보고하지 않으면 사용자가 잘못된 안심을 얻는다.
    """
    scanned: int = 0                                   # 분석에 성공한 파일 수
    skipped_too_large: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)  # (경로, 사유)
    partial: list[str] = field(default_factory=list)             # 구문오류로 일부만 분석

    @property
    def total(self) -> int:
        return self.scanned + len(self.skipped_too_large) + len(self.failed)

    @property
    def complete(self) -> bool:
        return not self.failed and not self.skipped_too_large and not self.partial

    def summary(self) -> str:
        if self.complete:
            return f"파일 {self.scanned}개 전부 분석 완료"
        parts = [f"분석 {self.scanned}개"]
        if self.failed:
            parts.append(f"분석 실패 {len(self.failed)}개")
        if self.partial:
            parts.append(f"구문오류로 부분분석 {len(self.partial)}개")
        if self.skipped_too_large:
            parts.append(f"크기 초과 제외 {len(self.skipped_too_large)}개")
        return " · ".join(parts)


def iter_source_files(root: str | Path, excludes: set[str] | None = None,
                      report: "ScanReport | None" = None):
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
                if report is not None:
                    report.skipped_too_large.append(str(p))
                continue
        except OSError:
            continue
        yield p


def parse_file(path: str | Path) -> tuple[ir.Module, bytes, str, bool]:
    """파일 하나를 파싱해 (IR 모듈, 원본 바이트, 언어이름, 구문오류여부) 반환.

    tree-sitter 는 깨진 소스에도 예외를 던지지 않고 ERROR 노드를 넣는다.
    따라서 "예외가 안 났다"는 분석이 온전했다는 뜻이 아니다 — has_error 를 봐야 한다.
    """
    path = Path(path)
    lang = loader.language_name_for(path)
    src = path.read_bytes()
    tree = loader.parse_source(src, language=lang)
    module = normalize.normalize(tree, file=str(path), language=lang)
    return module, src, lang, tree.root_node.has_error


def scan_file(path: str | Path, rules: list[Rule] | None = None) -> list[Finding]:
    """단일 파일 스캔(그 파일 안에서만 프로시저간 분석)."""
    path = Path(path)
    module, src, lang, _ = parse_file(path)
    if rules is None:
        rules = load_rules(language=lang)
    return engine.analyze(module, src, [r for r in rules if lang in r.languages])


def scan_path(root: str | Path, rules: list[Rule] | None = None,
              excludes: set[str] | None = None) -> tuple[list[Finding], ScanReport]:
    """디렉터리(또는 단일 파일) 스캔. 반환: (findings, 무결성 보고).

    성능 메모: 요약 계산은 (규칙 수 × 함수 수 × 파라미터 수 × 반복) 에 비례한다.
    대형 프로젝트에서 느려지면 규칙별 소스/싱크 사전 필터링이 다음 최적화 지점이다.
    """
    root = Path(root)
    if rules is None:
        rules = load_rules()

    report = ScanReport()
    files = [root] if root.is_file() else list(iter_source_files(root, excludes, report))

    # 1) 전부 파싱. 한 파일 실패가 전체 스캔을 죽이지는 않되, 조용히 넘기지도 않는다.
    parsed: list[tuple[Path, ir.Module, bytes, str]] = []
    for f in files:
        try:
            module, src, lang, has_error = parse_file(f)
        except Exception as e:
            report.failed.append((str(f), f"{type(e).__name__}: {e}"))
            continue
        if has_error:
            report.partial.append(str(f))
        parsed.append((f, module, src, lang))

    report.scanned = len(parsed)
    if not parsed:
        return [], report

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
    return findings, report
