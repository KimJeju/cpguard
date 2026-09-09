"""OWASP Benchmark 기반 탐지 성능 평가 (Java · Python).

OWASP Benchmark v1.2 는 2,740 개의 Java 테스트케이스에 대해 "이 파일에 해당 취약점이
실제로 존재하는가"를 라벨링한 정답지(expectedresults-1.2.csv)를 함께 제공한다.
같은 취약 유형에 대해 취약한 구현과 안전한 구현이 짝으로 들어 있어, 재현율뿐 아니라
오탐률까지 규모 있게 측정할 수 있다.

측정 대상은 **데이터 흐름(taint) 분석의 대상이 되는 유형**으로 한정한다. Benchmark 의
weakrand·crypto·hash·securecookie 는 "위험한 API 를 썼는가"를 보는 설정 점검 항목이고,
trustbound 는 세션 속성 신뢰 경계 문제라 CPGuard 의 taint 규칙 대상이 아니다. 대상 밖
유형을 정답 없이 집계하면 수치가 왜곡되므로 별도로 표시하고 지표에서 제외한다.

코퍼스는 세 가지를 지원한다. 정답지 파일(또는 표시 디렉터리)로 자동 판별한다.
  - OWASP Benchmark v1.2 (Java)   expectedresults-1.2.csv
  - OWASP Benchmark for Python    expectedresults-0.1.csv
  - PHP Vulnerability test suite   Injection/ 디렉터리 (라벨이 경로에 safe/unsafe 로 있다)

PHP 스위트는 NIST SAMATE 의 Bertrand Stivalet 생성 코퍼스다. 정답지 파일이 따로 없고
경로가 곧 라벨이다: <유형>/CWE_89/unsafe/....php

사용:
    python bench/owasp_benchmark.py <코퍼스 경로> [--json out.json] [--limit N]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpguard.scanner import scan_file, scan_path  # noqa: E402
from cpguard.taint.spec import load_rules  # noqa: E402

# Benchmark 카테고리 → CPGuard 규칙. 값이 None 이면 taint 분석 대상이 아니라는 뜻.
#
# 대상 밖 유형(weakrand·crypto·hash·securecookie·trustbound 등)은 "위험한 API 를 썼는가"를
# 보는 설정 점검 항목이라 taint 규칙이 없다. 정답 없이 집계하면 수치가 왜곡되므로 제외한다.
JAVA_CATEGORY_RULE = {
    "sqli": "java.sqli",
    "cmdi": "java.command-injection",
    "pathtraver": "java.path-traversal",
    "xss": "java.xss",
    "ldapi": "java.ldap-injection",
    "xpathi": "java.xpath-injection",
    "weakrand": None,
    "crypto": None,
    "hash": None,
    "trustbound": None,
    "securecookie": None,
}

#: PHP 스위트의 CWE 폴더 -> 우리 규칙. 우리 규칙이 없는 CWE 는 지표에서 뺀다.
PHP_CATEGORY_RULE = {
    "CWE_78": "php.command-injection",
    "CWE_79": "php.xss",
    "CWE_89": "php.sqli",
    "CWE_95": "php.code-injection",     # eval 계열 — 우리 규칙은 CWE-94 로 잡는다
    "CWE_98": "php.file-inclusion",
    "CWE_601": "php.open-redirect",
    # 아래는 php 규칙이 없거나 데이터 흐름 대상이 아니다 -> 지표에서 제외
    "CWE_90": None,        # LDAP 주입
    "CWE_91": None,        # XML/XPath 주입
    "CWE_209": None,
    "CWE_311": None,
    "CWE_327": None,
    "CWE_862_SQL": None,
    "CWE_862_XPath": None,
    "CWE_862_Fopen": None,
}

PYTHON_CATEGORY_RULE = {
    "sqli": "py.sqli",
    "cmdi": "py.command-injection",
    "pathtraver": "py.path-traversal",
    "xss": "py.xss",
    "codeinj": "py.code-injection",
    # 아래는 py 규칙이 없거나 데이터 흐름 대상이 아니다 → 지표에서 제외
    "weakrand": None,
    "hash": None,
    "securecookie": None,
    "trustbound": None,
    "xpathi": None,
    "ldapi": None,
    "xxe": None,
    "deserialization": None,
    "redirect": None,
}


#: BenchProctor 카테고리 -> 규칙 접미. 언어 접두(js/go/ruby/cpp)는 파일 확장자로 정한다.
#: 여기 없는 카테고리(weakhash·securecookie·csrf 등)는 설정·API 사용 점검이라 taint 대상이
#: 아니다 — 기존 코퍼스와 같은 기준으로 지표에서 뺀다.
BENCHPROCTOR_CATEGORY = {
    "sqli": "sqli",
    "nosql": "sqli",
    "cmdi": "command-injection",
    "genericcmdi": "command-injection",
    "argument_injection": "command-injection",
    "xss": "xss",
    "basic_xss": "xss",
    "pathtraver": "path-traversal",
    "ssrf": "ssrf",
    "cloud_ssrf_metadata": "ssrf",
    "redirect": "open-redirect",
    "codeinj": "code-injection",
    "eval_injection": "code-injection",
    "deserial": "deserialization",
    "xpathi": "xpath-injection",
    "ldapi": "ldap-injection",
}

#: 데이터 흐름 대상이지만 **우리가 규칙을 갖고 있지 않은** 유형. 설정 점검이라 빼는 것과
#: 구별해서 보고한다 — 전자는 범위 밖이고 이쪽은 우리 쪽 공백이다. 있지도 않은 규칙에
#: 매핑해 두면 그 유형이 전부 미탐으로 잡혀, 가진 규칙의 성능까지 같이 깎인다.
BENCHPROCTOR_NO_RULE = {
    "nosql": "NoSQL 주입", "ssti": "템플릿 주입", "el_injection": "표현식 언어 주입",
    "prototypepollution": "프로토타입 오염", "crlfinjection": "CRLF 주입",
    "loginjection": "로그 주입", "csv_injection": "CSV 수식 주입",
    "xxe": "XXE", "fileupload": "위험한 파일 업로드", "idor": "IDOR",
    "intoverflow": "정수 오버플로", "null_deref": "널 역참조",
    "resourceexhaust": "자원 고갈",
}

#: SARD C# 스위트의 CWE -> 규칙 접미.
SARD_CSHARP_CWE = {
    "cwe_89": "sqli",
    "cwe_78": "command-injection",
    "cwe_22": "path-traversal",
    "cwe_90": "ldap-injection",
    "cwe_91": "xpath-injection",
}


def rule_map(prefix: str, table: dict) -> dict:
    """카테고리 -> 규칙 id. 그 언어에 규칙이 없으면 None(지표에서 제외).

    규칙 목록을 실제로 읽어서 정한다 — 없는 규칙을 정답지에 넣어 두면 그 유형이
    전부 미탐으로 잡혀 수치가 실제보다 나쁘게 나온다.
    """
    have = {r.id for r in load_rules(user_dir=False)}
    out = {cat: (rid if (rid := f"{prefix}.{suffix}") in have else None)
           for cat, suffix in table.items()}
    if table is BENCHPROCTOR_CATEGORY:
        out.update(dict.fromkeys(BENCHPROCTOR_NO_RULE))   # 규칙 없음 -> 지표에서 제외
    return out


@dataclass
class Corpus:
    """코퍼스 하나의 생김새 — 정답지 위치, 테스트 파일 위치, 카테고리 매핑."""
    name: str
    answers: str                 # 루트 기준 정답지 CSV 경로
    testdir: str                 # 루트 기준 테스트코드 디렉터리
    glob: str
    category_rule: dict
    #: 정답지가 CSV 가 아니라 경로에 있는 코퍼스(PHP 스위트). testdir 아래를 훑는다.
    labels_in_path: bool = False
    #: 케이스 디렉터리마다 manifest.sarif 가 good/bad 를 선언하는 코퍼스(SARD C# 스위트).
    labels_in_manifest: bool = False
    #: 파일 이름과 정답지 키가 다른 코퍼스. benchmark_test_00178 -> BenchmarkTest00178
    camel_key: bool = False


CORPORA = (
    Corpus("OWASP Benchmark v1.2 (Java)", "expectedresults-1.2.csv",
           "src/main/java/org/owasp/benchmark/testcode", "BenchmarkTest*.java",
           JAVA_CATEGORY_RULE),
    Corpus("OWASP Benchmark for Python v0.1", "expectedresults-0.1.csv",
           "testcode", "BenchmarkTest*.py", PYTHON_CATEGORY_RULE),
    Corpus("PHP Vulnerability test suite (SAMATE)", "Injection",
           ".", "**/*.php", PHP_CATEGORY_RULE, labels_in_path=True),
)

#: BenchProctor 번들은 언어별로 확장자만 다르고 모양이 같다. 프레임워크 디렉터리
#: 하나(expectedresults-*.csv + testcode/)가 코퍼스 하나다.
BENCHPROCTOR_EXT = {".js": "js", ".ts": "js", ".go": "go", ".rb": "ruby",
                    ".c": "cpp", ".cpp": "cpp", ".cs": "csharp", ".py": "py",
                    ".java": "java", ".php": "php"}


def _benchproctor(root: Path) -> Corpus | None:
    """<언어>/<프레임워크>/ 아래 expectedresults-*.csv 와 testcode/ 가 있으면 그 코퍼스."""
    answers = next(iter(sorted(root.glob("expectedresults-*.csv"))), None)
    testdir = root / "testcode"
    if answers is None or not testdir.is_dir():
        return None
    sample = next((q for q in sorted(testdir.glob("benchmark_test_*"))), None)
    if sample is None:
        return None
    prefix = BENCHPROCTOR_EXT.get(sample.suffix)
    if prefix is None:
        return None
    return Corpus(f"BenchProctor {root.parent.name}/{root.name}", answers.name,
                  "testcode", f"benchmark_test_*{sample.suffix}",
                  rule_map(prefix, BENCHPROCTOR_CATEGORY), camel_key=True)


def _sard_manifest(root: Path) -> Corpus | None:
    """SARD 케이스 디렉터리 묶음(<id>-v1.0.0/manifest.sarif + src/)."""
    if next(iter(root.glob("*/manifest.sarif")), None) is None:
        return None
    return Corpus("C# Vulnerability Test Suite (SARD)", "", ".", "**/src/*.cs",
                  rule_map("csharp", SARD_CSHARP_CWE), labels_in_manifest=True)


def detect_corpus(root: Path) -> Corpus:
    for probe in (_benchproctor, _sard_manifest):
        if (c := probe(root)) is not None:
            return c
    for c in CORPORA:
        marker = root / c.answers
        if marker.is_dir() if c.labels_in_path else marker.is_file():
            return c
    raise SystemExit(
        f"OWASP Benchmark 코퍼스가 아닙니다(정답지를 찾을 수 없음): {root}\n"
        "  기대: " + " 또는 ".join(c.answers for c in CORPORA))


_RULES = None


def _init() -> None:
    global _RULES
    _RULES = load_rules()


def _scan_one(path_str: str) -> tuple[str, tuple[list[str], int, int]]:
    """(파일이름, (탐지 규칙들, 탐지 수, 불확실 수))."""
    path = Path(path_str)
    try:
        found = scan_file(path, _RULES)
    except Exception as e:
        return path.stem, ([f"<error:{type(e).__name__}>"], 0, 0)
    return path.stem, (sorted({f.rule_id for f in found}), len(found),
                       sum(1 for f in found if f.uncertain))


def _camel(stem: str) -> str:
    """benchmark_test_00178 -> BenchmarkTest00178 (BenchProctor 의 정답지 키)."""
    return "".join(part.capitalize() for part in stem.split("_")[:-1]) + stem.split("_")[-1]


def load_expected(root: Path, corpus: Corpus) -> dict[str, tuple[str, bool]]:
    if corpus.labels_in_manifest:
        # 케이스 디렉터리마다 manifest.sarif 가 state(good/bad)를, 파일 이름이 CWE 를 말한다.
        out: dict[str, tuple[str, bool]] = {}
        for m in root.glob("*/manifest.sarif"):
            try:
                props = json.loads(m.read_text(encoding="utf-8"))["runs"][0]["properties"]
            except Exception:
                continue
            for src in (m.parent / "src").glob("*.cs"):
                out[src.stem] = (src.name.split("__")[0], props.get("state") == "bad")
        return out
    if corpus.labels_in_path:
        # 경로가 곧 정답이다: <유형>/CWE_89/unsafe/....php
        out: dict[str, tuple[str, bool]] = {}
        for p in root.rglob("*.php"):
            parts = p.parts
            cwe = next((x for x in parts if x.startswith("CWE_")), None)
            if cwe is None or ("safe" not in parts and "unsafe" not in parts):
                continue
            out[p.stem] = (cwe, "unsafe" in parts)
        return out
    csv_path = root / corpus.answers
    expected = {}
    with csv_path.open(encoding="utf-8") as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            name, category, real = row[0].strip(), row[1].strip(), row[2].strip()
            expected[name] = (category, real.lower() == "true")
    return expected


def metrics(c: dict[str, int]) -> dict:
    tp, fn, fp, tn = c["TP"], c["FN"], c["FP"], c["TN"]
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {**c, "recall": recall, "precision": precision, "f1": f1,
            "false_positive_rate": fpr,
            # OWASP Benchmark 공식 점수: 정탐률 - 오탐률 (Youden index)
            "benchmark_score": recall - fpr}

def _scan_project(root: Path, stems: set[str], workers: int | None
                  ) -> dict[str, tuple[list[str], int, int]]:
    """코퍼스 전체를 한 번에 스캔하고 결과를 테스트 파일별로 나눈다.

    파일 단위 스캔과 달리 파일 경계를 넘는 함수 요약이 붙는다. 파이썬 코퍼스처럼
    테스트가 공용 헬퍼(helpers/utils.py)를 부르는 구조에서는 이쪽이 실제 진단에
    가깝다 — 파일 단위로 재면 그 헬퍼가 늘 미해석으로 남아 흐름 전부에 '불확실'
    표시가 찍힌다.

    흐름이 여러 파일에 걸치므로 finding 은 트레이스가 지나간 테스트 파일에 귀속시킨다.
    """
    results: dict[str, tuple[list[str], int, int]] = {
        stem: ([], 0, 0) for stem in stems}
    findings, _report = scan_path(root, jobs=workers or 1)
    for f in findings:
        touched = {Path(st.loc.file).stem for st in f.steps} & stems
        for stem in touched:
            hits, n_found, n_uncertain = results[stem]
            if f.rule_id not in hits:
                hits.append(f.rule_id)
            results[stem] = (hits, n_found + 1, n_uncertain + bool(f.uncertain))
    return {k: (sorted(v[0]), v[1], v[2]) for k, v in results.items()}


def evaluate(root: Path, limit: int | None = None, workers: int | None = None,
             mode: str = "project") -> dict:
    corpus = detect_corpus(root)
    category_rule = corpus.category_rule
    expected = load_expected(root, corpus)
    src = root.joinpath(*corpus.testdir.split("/"))
    key = _camel if corpus.camel_key else (lambda s: s)
    files = sorted(p for p in src.glob(corpus.glob) if key(p.stem) in expected)
    if limit:
        files = files[:limit]

    if mode == "project":
        results = _scan_project(root, {p.stem for p in files}, workers)
        if corpus.camel_key:      # 정답지 키로 맞춰 놓는다
            results = {key(k): v for k, v in results.items()}
    else:
        with ProcessPoolExecutor(max_workers=workers, initializer=_init) as pool:
            results = {key(k): v for k, v in
                       pool.map(_scan_one, [str(p) for p in files], chunksize=16)}

    # 카테고리별 혼동행렬
    cats: dict[str, dict[str, int]] = {}
    errors = found_total = uncertain_total = 0
    for name, (hits, n_found, n_uncertain) in results.items():
        found_total += n_found
        uncertain_total += n_uncertain
        category, real = expected[name]
        if any(h.startswith("<error:") for h in hits):
            errors += 1
        rule = category_rule.get(category)
        c = cats.setdefault(category, {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "total": 0})
        c["total"] += 1
        if rule is None:
            continue
        hit = rule in hits
        if real:
            c["TP" if hit else "FN"] += 1
        else:
            c["FP" if hit else "TN"] += 1


    scored = {k: metrics(v) for k, v in sorted(cats.items()) if category_rule.get(k)}
    excluded = {k: v["total"] for k, v in sorted(cats.items()) if not category_rule.get(k)}

    agg = {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "total": 0}
    for v in scored.values():
        for k in agg:
            agg[k] += v[k]
    overall = metrics(agg)

    return {
        "benchmark": corpus.name,
        "scan_mode": mode,
        "files_scanned": len(results),
        "parse_errors": errors,
        "per_category": scored,
        "excluded_categories": excluded,
        "overall": overall,
        # 진단원이 "이건 라이브러리 안에서 정제됐을 수도 있다"고 다시 봐야 하는 비율.
        # 오탐률과 별개로 검토 비용을 직접 나타낸다.
        "uncertain": {"findings": found_total, "uncertain": uncertain_total,
                      "ratio": (uncertain_total / found_total) if found_total else 0.0},
    }


def render(r: dict) -> str:
    out = [
        "=" * 86,
        f"{r['benchmark']} — CPGuard 탐지 성능",
        "=" * 86,
        f"스캔한 파일 {r['files_scanned']}개 (파싱 오류 {r['parse_errors']}건) · "
        f"{'프로젝트 단위(파일 간 요약 적용)' if r.get('scan_mode') == 'project' else '파일 단위'}",
        "",
        f"{'카테고리':<14}{'대상':>6}{'TP':>6}{'FN':>6}{'FP':>6}{'TN':>6}"
        f"{'재현율':>10}{'정밀도':>10}{'F1':>8}{'오탐률':>10}{'점수':>8}",
        "-" * 86,
    ]
    for cat, m in r["per_category"].items():
        out.append(
            f"{cat:<14}{m['total']:>6}{m['TP']:>6}{m['FN']:>6}{m['FP']:>6}{m['TN']:>6}"
            f"{m['recall']:>9.1%}{m['precision']:>10.1%}{m['f1']:>8.3f}"
            f"{m['false_positive_rate']:>10.1%}{m['benchmark_score']:>8.3f}")
    o = r["overall"]
    out += [
        "-" * 86,
        f"{'전체':<14}{o['total']:>6}{o['TP']:>6}{o['FN']:>6}{o['FP']:>6}{o['TN']:>6}"
        f"{o['recall']:>9.1%}{o['precision']:>10.1%}{o['f1']:>8.3f}"
        f"{o['false_positive_rate']:>10.1%}{o['benchmark_score']:>8.3f}",
        "",
    ]
    ex = r["excluded_categories"]
    gap = {k: v for k, v in ex.items() if k in BENCHPROCTOR_NO_RULE}
    ex = {k: v for k, v in ex.items() if k not in gap}
    if ex:
        out.append("지표 제외 (데이터 흐름 분석 대상이 아닌 설정·API 사용 점검 항목):")
        out.append("  " + ", ".join(f"{k}({v})" for k, v in ex.items()))
    if gap:
        out.append("")
        out.append("지표 제외 — 흐름 분석 대상이지만 우리에게 그 규칙이 없다(공백):")
        out.append("  " + ", ".join(f"{k}({v})" for k, v in gap.items()))
    u = r.get("uncertain")
    if u and u["findings"]:
        out.append("")
        out.append(f"불확실 표시: 탐지 {u['findings']}건 중 {u['uncertain']}건 "
                   f"({u['ratio']:.1%}) — 진단원이 다시 봐야 하는 양")
    out.append("")
    out.append("점수 = 재현율 - 오탐률 (OWASP Benchmark 공식 지표, 무작위 추측 = 0.000)")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="OWASP Benchmark 기반 CPGuard 탐지 성능 평가")
    ap.add_argument("root", help="Benchmark 코퍼스 경로 (Java 또는 Python)")
    ap.add_argument("--json", help="결과를 JSON 으로 저장")
    ap.add_argument("--limit", type=int, help="앞에서 N개만 (빠른 확인용)")
    ap.add_argument("--workers", type=int, help="병렬 프로세스 수")
    ap.add_argument("--mode", choices=("project", "file"), default="project",
                    help="project=코퍼스 전체를 한 번에(파일 간 요약 적용, 기본), "
                         "file=파일 단위(예전 수치와 비교용)")
    args = ap.parse_args()

    result = evaluate(Path(args.root), args.limit, args.workers, args.mode)
    # JSON 을 먼저 저장한다 — cp949 콘솔에서 render() 출력이
    # UnicodeEncodeError 로 죽으면 몇 분 돌린 결과가 통째로 날아간다.
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(render(result))
    if args.json:
        print(f"\nJSON 저장: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
