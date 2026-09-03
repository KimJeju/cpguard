"""프로젝트 디렉터리 스캔 오케스트레이션.

두 축이 서로 다른 파일 집합을 본다.
  - 데이터 흐름(taint) 축 : 파서가 있는 언어 파일만 (js/ts/php/py)
  - 패턴 축              : 모든 텍스트 파일 (.env·.properties·.yml·.sql·.xml 까지)
비밀정보·개인정보는 소스가 아니라 설정 파일과 덤프에 더 많이 있으므로 두 번째가 중요하다.

파일 워크 -> 전체 파싱 -> 공용 함수 레지스트리/요약 -> 파일별 분석 -> Finding 목록.
CLI 와 웹 대시보드가 공통으로 쓰는 진입점이다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import ir
from .cpg.callgraph import collect_functions
from .parse import loader, normalize
from .patterns import (PatternRule, is_text_candidate, load_pattern_rules,
                       read_text_lenient, rules_for, scan_filename, scan_text)
from .report.finding import Finding
from .taint import engine
from .taint.spec import Rule, load_rules

# 스캔에서 제외할 디렉터리 (의존성·빌드 산출물·IDE·캐시)
DEFAULT_EXCLUDES = {
    "node_modules", "bower_components", ".git", ".svn", ".hg", "dist", "build", "out",
    "target", "bin", "obj", "coverage", ".next", ".nuxt", "vendor", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".venv", "venv", "env", ".idea", ".vscode",
    ".gradle", ".terraform", "Pods", ".cache", "logs", "tmp", "temp",
}

MAX_FILE_BYTES = 2_000_000        # 파서에 넣을 소스 상한 (미니파이 번들 등)
MAX_TEXT_FILE_BYTES = 20_000_000  # 패턴 축이 훑을 텍스트 상한 (SQL 덤프는 클 수 있다)


@dataclass
class ScanReport:
    """스캔 무결성 보고.

    "취약점 0건"이 정말 안전하다는 뜻인지, 아니면 파일을 못 읽어서인지 구분해야 한다.
    조용히 건너뛴 파일을 보고하지 않으면 사용자가 잘못된 안심을 얻는다.
    """
    scanned: int = 0                                   # 파싱·분석에 성공한 소스 파일 수
    text_scanned: int = 0                              # 패턴 축이 훑은 텍스트 파일 수(소스 포함)
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
        head = f"소스 {self.scanned}개"
        if self.text_scanned > self.scanned:
            head += f" · 텍스트 {self.text_scanned}개"
        if self.complete:
            return f"{head} 전부 분석 완료"
        parts = [head]
        if self.failed:
            parts.append(f"분석 실패 {len(self.failed)}개")
        if self.partial:
            parts.append(f"구문오류로 부분분석 {len(self.partial)}개")
        if self.skipped_too_large:
            parts.append(f"크기 초과 제외 {len(self.skipped_too_large)}개")
        return " · ".join(parts)


def _excluded(p: Path, excludes: set[str]) -> bool:
    return any(part in excludes for part in p.parts) or p.name.startswith("~$")


def iter_source_files(root: str | Path, excludes: set[str] | None = None,
                      report: "ScanReport | None" = None):
    """파서가 있는 언어의 소스 파일."""
    root = Path(root)
    excludes = DEFAULT_EXCLUDES if excludes is None else excludes
    for p in root.rglob("*"):
        if not p.is_file() or _excluded(p, excludes):
            continue
        if p.suffix.lower() not in loader.SUPPORTED_EXTENSIONS:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                if report is not None:
                    report.skipped_too_large.append(str(p))
                continue
        except OSError:
            continue
        yield p


def iter_text_files(root: str | Path, excludes: set[str] | None = None):
    """패턴 축이 볼 모든 텍스트 파일 (바이너리·잠금파일·미니파이 제외)."""
    root = Path(root)
    excludes = DEFAULT_EXCLUDES if excludes is None else excludes
    for p in root.rglob("*"):
        if not p.is_file() or _excluded(p, excludes):
            continue
        try:
            size = p.stat().st_size
        except OSError:
            continue
        if size == 0 or size > MAX_TEXT_FILE_BYTES:
            continue
        if not is_text_candidate(p):
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


def _pattern_scan_file(path: Path, pattern_rules: list[PatternRule],
                       language: str | None, label: str | None = None) -> list[Finding]:
    """파일명 점검 + 본문 패턴 점검."""
    out: list[Finding] = []
    fn = scan_filename(path, label)
    if fn is not None:
        out.append(fn)
    pr = rules_for(pattern_rules, language, path.suffix.lower())
    if pr:
        out.extend(scan_text(read_text_lenient(path), label or str(path), pr))
    return out


def scan_file(path: str | Path, rules: list[Rule] | None = None,
              pattern_rules: list[PatternRule] | None = None) -> list[Finding]:
    """단일 파일 스캔(그 파일 안에서만 프로시저간 분석) + 패턴 규칙."""
    path = Path(path)
    if pattern_rules is None:
        pattern_rules = load_pattern_rules()

    if path.suffix.lower() not in loader.SUPPORTED_EXTENSIONS:
        return _pattern_scan_file(path, pattern_rules, None)

    module, src, lang, _ = parse_file(path)
    rl = loader.rule_language(lang)
    if rules is None:
        rules = load_rules(language=rl)
    out = engine.analyze(module, src, [r for r in rules if rl in r.languages])
    out += _pattern_scan_file(path, pattern_rules, rl)
    return out


def scan_path(root: str | Path, rules: list[Rule] | None = None,
              excludes: set[str] | None = None, progress=None,
              secrets_only: bool = False) -> tuple[list[Finding], ScanReport]:
    """디렉터리(또는 단일 파일) 스캔. 반환: (findings, 무결성 보고).

    secrets_only: True 면 데이터 흐름(taint) 축을 건너뛰고 패턴 축만 돈다
    (하드코딩 비밀정보·개인정보·설정 위생 빠른 점검).
    progress: 선택적 콜백 progress(phase, done, total, findings). UI 진행바용.
    phase 는 'parse'/'dataflow'/'pattern'/'done'. total 이 0 이면 진행률 미상(스피너).

    성능 메모: 요약 계산은 (규칙 수 × 함수 수 × 파라미터 수 × 반복) 에 비례한다.
    대형 프로젝트에서 느려지면 규칙별 소스/싱크 사전 필터링이 다음 최적화 지점이다.
    """
    root = Path(root)
    if rules is None:
        rules = load_rules()
    pattern_rules = load_pattern_rules()
    report = ScanReport()
    _p = progress or (lambda *a, **k: None)

    if root.is_file():
        findings = scan_file(root, rules, pattern_rules)
        report.scanned = 1 if root.suffix.lower() in loader.SUPPORTED_EXTENSIONS else 0
        report.text_scanned = 1
        return findings, report

    findings: list[Finding] = []

    if not secrets_only:
        # 1) 소스 전부 파싱. 한 파일 실패가 전체를 죽이지는 않되, 조용히 넘기지도 않는다.
        src_files = list(iter_source_files(root, excludes, report))
        _p("parse", 0, len(src_files), 0)
        parsed: list[tuple[Path, ir.Module, bytes, str]] = []
        source_paths: set[Path] = set()
        for i, f in enumerate(src_files, 1):
            source_paths.add(f)
            try:
                module, src, lang, has_error = parse_file(f)
            except Exception as e:
                report.failed.append((str(f), f"{type(e).__name__}: {e}"))
                _p("parse", i, len(src_files), 0)
                continue
            if has_error:
                report.partial.append(str(f))
            parsed.append((f, module, src, lang))
            _p("parse", i, len(src_files), 0)
        report.scanned = len(parsed)

        # 2) 데이터 흐름 축: 파일 경계를 넘는 공용 레지스트리와 규칙별 요약
        if parsed:
            _p("dataflow", 0, 0, len(findings))  # 요약 계산은 파일 단위 진행률이 없다 → 스피너
            registry = collect_functions([(m, src, str(p)) for p, m, src, _ in parsed])
            summaries_by_rule = {r.id: engine.compute_summaries(registry, r) for r in rules}
            for i, (path, module, src, lang) in enumerate(parsed, 1):
                rl = loader.rule_language(lang)
                applicable = [r for r in rules if rl in r.languages]
                if applicable:
                    findings.extend(engine.analyze(
                        module, src, applicable,
                        registry=registry, summaries_by_rule=summaries_by_rule,
                    ))
                _p("dataflow", i, len(parsed), len(findings))

    # 3) 패턴 축: 모든 텍스트 파일 (소스는 언어 규칙까지, 그 외는 언어무관 규칙만)
    text_files = list(iter_text_files(root, excludes))
    _p("pattern", 0, len(text_files), len(findings))
    for i, path in enumerate(text_files, 1):
        lang: str | None = None
        if path.suffix.lower() in loader.SUPPORTED_EXTENSIONS:
            try:
                lang = loader.rule_language(loader.language_name_for(path))
            except Exception:
                lang = None
        try:
            findings.extend(_pattern_scan_file(path, pattern_rules, lang))
            report.text_scanned += 1
        except Exception as e:
            report.failed.append((str(path), f"pattern: {type(e).__name__}: {e}"))
        _p("pattern", i, len(text_files), len(findings))

    _p("done", report.scanned, report.scanned, len(findings))

    return findings, report
