"""프로젝트 디렉터리 스캔 오케스트레이션.

두 축이 서로 다른 파일 집합을 본다.
  - 데이터 흐름(taint) 축 : 파서가 있는 언어 파일만 (js/ts/php/py)
  - 패턴 축              : 모든 텍스트 파일 (.env·.properties·.yml·.sql·.xml 까지)
비밀정보·개인정보는 소스가 아니라 설정 파일과 덤프에 더 많이 있으므로 두 번째가 중요하다.

파일 워크 -> 전체 파싱 -> 공용 함수 레지스트리/요약 -> 파일별 분석 -> Finding 목록.
CLI 와 웹 대시보드가 공통으로 쓰는 진입점이다.
"""
from __future__ import annotations

import hashlib
import os
import pickle
from dataclasses import dataclass, field
from pathlib import Path

# 파싱 캐시: 같은 (경로+내용)이면 tree-sitter 재파싱을 생략(증분 재스캔 최적화).
# IR 스키마가 바뀌면 이 버전을 올려 캐시를 무효화한다.
#
# 보안: 캐시는 CPGuard 가 직접 만든 자체 파싱 결과를 사용자 홈(~/.cpguard/cache,
# 앱 전용·비공개 디렉터리)에 쓴 것만 unpickle 한다 — 외부/신뢰불가 입력이 아니다.
# 그 디렉터리에 쓸 수 있는 주체는 이미 앱과 동일한 신뢰 수준을 가진다.
_PARSE_CACHE_VER = 1


def _parse_cache_dir() -> Path:
    return Path(os.environ.get("CPGUARD_HOME", Path.home() / ".cpguard")) / "cache" / "parse"

from . import ir
from .cpg.callgraph import collect_functions
from .parse import loader, normalize
from .extract import longpath
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


def _rule_sink_literals(rule: Rule) -> frozenset[str]:
    """규칙 sink 의 마지막 경로 세그먼트 집합(엔진의 이름 정확 일치와 동일 기준).
    'child_process.exec' -> 'exec'. 소스에 이 리터럴이 없으면 그 규칙의 sink 는 없다."""
    cache = _rule_sink_literals.__dict__.setdefault("_c", {})
    if rule.id in cache:
        return cache[rule.id]
    lits = frozenset(c.split(".")[-1] for s in rule.sinks for c in s.callee if c)
    cache[rule.id] = lits
    return lits


def _all_sink_literals(rules: list[Rule]) -> frozenset[str]:
    out: set[str] = set()
    for r in rules:
        out |= _rule_sink_literals(r)
    return frozenset(out)


def _parse_one(path_str: str):
    """멀티프로세스 파싱 워커(최상위 함수라 pickle 가능). 예외는 사유 문자열로."""
    try:
        module, src, lang, has_error = parse_file(path_str)
        return (path_str, module, src, lang, has_error, None)
    except Exception as e:
        return (path_str, None, None, None, False, f"{type(e).__name__}: {e}")


def _excluded(p: Path, excludes: set[str]) -> bool:
    return any(part in excludes for part in p.parts) or p.name.startswith("~$")


def _walk_root(root: Path) -> Path:
    r"""탐색용 루트. Windows 에서 \\?\ 접두를 붙여야 260자 넘는 경로가 열거된다.

    접두 없이 rglob 하면 긴 경로 파일은 조용히 빠지고 무결성 보고에도 안 남는다
    (= "0건"이 안전으로 보이는 최악의 실패). 열거된 경로는 I/O 에도 그대로 쓴다."""
    if os.name != "nt":
        return root
    return Path(longpath(root))


def iter_source_files(root: str | Path, excludes: set[str] | None = None,
                      report: "ScanReport | None" = None):
    """파서가 있는 언어의 소스 파일."""
    root = _walk_root(Path(root))
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
    root = _walk_root(Path(root))
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


def parse_file(path: str | Path, use_cache: bool = True) -> tuple[ir.Module, bytes, str, bool]:
    """파일 하나를 파싱해 (IR 모듈, 원본 바이트, 언어이름, 구문오류여부) 반환.

    tree-sitter 는 깨진 소스에도 예외를 던지지 않고 ERROR 노드를 넣는다.
    따라서 "예외가 안 났다"는 분석이 온전했다는 뜻이 아니다 — has_error 를 봐야 한다.

    use_cache: (경로+내용) 해시로 파싱 결과를 캐시해 재파싱을 생략한다. 키에 경로를
    포함하므로 Loc.file 이 다른 파일과 섞이지 않는다(같은 프로젝트 재스캔이 주 이득).
    """
    path = Path(path)
    lang = loader.language_name_for(path)
    src = path.read_bytes()

    cf = None
    if use_cache:
        key = hashlib.sha1(f"{path}\0".encode() + src).hexdigest()
        cf = _parse_cache_dir() / f"{key}-{lang}-v{_PARSE_CACHE_VER}.pkl"
        try:
            with open(cf, "rb") as fh:
                module, has_error = pickle.load(fh)
            return module, src, lang, has_error
        except Exception:
            pass  # 캐시 미스/손상 → 그냥 파싱

    tree = loader.parse_source(src, language=lang)
    module = normalize.normalize(tree, file=str(path), language=lang)
    has_error = tree.root_node.has_error

    if cf is not None:
        try:
            cf.parent.mkdir(parents=True, exist_ok=True)
            with open(cf, "wb") as fh:
                pickle.dump((module, has_error), fh)
        except Exception:
            pass  # 캐시 쓰기 실패는 무시
    return module, src, lang, has_error


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
              secrets_only: bool = False, jobs: int = 1) -> tuple[list[Finding], ScanReport]:
    """디렉터리(또는 단일 파일) 스캔. 반환: (findings, 무결성 보고).

    jobs: 파싱 병렬 워커 수(기본 1=순차). 대형 프로젝트에서만 이득. frozen 앱에서
    쓰려면 진입점에 multiprocessing.freeze_support() 가 있어야 한다(이미 적용).
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

        def _accept(res, i):
            spath, module, src, lang, has_error, err = res
            if err is not None:
                report.failed.append((spath, err))
            else:
                if has_error:
                    report.partial.append(spath)
                parsed.append((Path(spath), module, src, lang))
            _p("parse", i, len(src_files), 0)

        if jobs and jobs > 1 and len(src_files) > 1:
            from concurrent.futures import ProcessPoolExecutor
            with ProcessPoolExecutor(max_workers=jobs) as ex:
                for i, res in enumerate(ex.map(_parse_one, [str(f) for f in src_files]), 1):
                    _accept(res, i)
        else:
            for i, f in enumerate(src_files, 1):
                _accept(_parse_one(str(f)), i)
        report.scanned = len(parsed)

        # 2) 데이터 흐름 축: 파일 경계를 넘는 공용 레지스트리와 규칙별 요약
        if parsed:
            _p("dataflow", 0, 0, len(findings))  # 요약 계산은 파일 단위 진행률이 없다 → 스피너

            # ---- 싱크 사전 필터링 (대규모 최적화, 정확도 보존) ----
            # sink 는 이름 정확 일치로만 매칭된다(엔진 한계와 동일). 소스에 그 이름조차
            # 없는 규칙은 전역에서 생략한다. 파일 단위 필터는 요약 계산 후 수행한다:
            # 각 규칙의 관심 이름 = sink 리터럴 ∪ (sink 에 닿는 요약을 가진 함수 이름).
            # 크로스파일 흐름의 finding 은 sink 를 안 가진 '호출부'에서 emit 되므로,
            # sink_paths 함수 이름을 포함해야 그 호출부 파일을 놓치지 않는다.
            file_text = {str(p): src.decode("utf-8", "ignore") for p, m, src, _ in parsed}
            all_lits = _all_sink_literals(rules)
            present = {lit for t in file_text.values() for lit in all_lits if lit in t}
            active = [r for r in rules if _rule_sink_literals(r) & present]

            registry = collect_functions([(m, src, str(p)) for p, m, src, _ in parsed])
            summaries_by_rule = {r.id: engine.compute_summaries(registry, r) for r in active}

            rule_names: dict = {}   # rule_id -> 이 규칙 분석이 의미있는 '관심 이름' 집합
            for r in active:
                names = set(_rule_sink_literals(r))
                for fname, summ in summaries_by_rule[r.id].items():
                    if summ.sink_paths:                      # 이 함수는 인자가 sink 에 닿는다
                        names.add(fname.split(".")[-1])      # 호출부 텍스트 매칭용 단순명
                rule_names[r.id] = names

            for i, (path, module, src, lang) in enumerate(parsed, 1):
                rl = loader.rule_language(lang)
                t = file_text[str(path)]
                applicable = [r for r in active if rl in r.languages
                              and any(n in t for n in rule_names[r.id])]
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
