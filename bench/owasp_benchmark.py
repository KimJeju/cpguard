"""OWASP Benchmark(Java) 기반 탐지 성능 평가.

OWASP Benchmark v1.2 는 2,740 개의 Java 테스트케이스에 대해 "이 파일에 해당 취약점이
실제로 존재하는가"를 라벨링한 정답지(expectedresults-1.2.csv)를 함께 제공한다.
같은 취약 유형에 대해 취약한 구현과 안전한 구현이 짝으로 들어 있어, 재현율뿐 아니라
오탐률까지 규모 있게 측정할 수 있다.

측정 대상은 **데이터 흐름(taint) 분석의 대상이 되는 유형**으로 한정한다. Benchmark 의
weakrand·crypto·hash·securecookie 는 "위험한 API 를 썼는가"를 보는 설정 점검 항목이고,
trustbound 는 세션 속성 신뢰 경계 문제라 CPGuard 의 taint 규칙 대상이 아니다. 대상 밖
유형을 정답 없이 집계하면 수치가 왜곡되므로 별도로 표시하고 지표에서 제외한다.

사용:
    python bench/owasp_benchmark.py <BenchmarkJava 경로> [--json out.json] [--limit N]
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpguard.scanner import scan_file  # noqa: E402
from cpguard.taint.spec import load_rules  # noqa: E402

# Benchmark 카테고리 → CPGuard 규칙. 값이 None 이면 taint 분석 대상이 아니라는 뜻.
CATEGORY_RULE = {
    "sqli": "java.sqli",
    "cmdi": "java.command-injection",
    "pathtraver": "java.path-traversal",
    "xss": "java.xss",
    "ldapi": "java.ldap-injection",
    "xpathi": "java.xpath-injection",
    # 아래는 데이터 흐름이 아니라 API 사용/설정 점검 항목 → 지표에서 제외
    "weakrand": None,
    "crypto": None,
    "hash": None,
    "trustbound": None,
    "securecookie": None,
}

_RULES = None


def _init() -> None:
    global _RULES
    _RULES = load_rules()


def _scan_one(path_str: str) -> tuple[str, list[str]]:
    path = Path(path_str)
    try:
        hits = sorted({f.rule_id for f in scan_file(path, _RULES)})
    except Exception as e:
        hits = [f"<error:{type(e).__name__}>"]
    return path.stem, hits


def load_expected(root: Path) -> dict[str, tuple[str, bool]]:
    csv_path = root / "expectedresults-1.2.csv"
    if not csv_path.is_file():
        raise SystemExit(f"Benchmark 경로가 아닙니다(expectedresults-1.2.csv 없음): {root}")
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

def evaluate(root: Path, limit: int | None = None, workers: int | None = None) -> dict:
    expected = load_expected(root)
    src = root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    files = sorted(p for p in src.glob("BenchmarkTest*.java") if p.stem in expected)
    if limit:
        files = files[:limit]

    with ProcessPoolExecutor(max_workers=workers, initializer=_init) as pool:
        results = dict(pool.map(_scan_one, [str(p) for p in files], chunksize=16))

    # 카테고리별 혼동행렬
    cats: dict[str, dict[str, int]] = {}
    errors = 0
    for name, hits in results.items():
        category, real = expected[name]
        if any(h.startswith("<error:") for h in hits):
            errors += 1
        rule = CATEGORY_RULE.get(category)
        c = cats.setdefault(category, {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "total": 0})
        c["total"] += 1
        if rule is None:
            continue
        hit = rule in hits
        if real:
            c["TP" if hit else "FN"] += 1
        else:
            c["FP" if hit else "TN"] += 1


    scored = {k: metrics(v) for k, v in sorted(cats.items()) if CATEGORY_RULE.get(k)}
    excluded = {k: v["total"] for k, v in sorted(cats.items()) if not CATEGORY_RULE.get(k)}

    agg = {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "total": 0}
    for v in scored.values():
        for k in agg:
            agg[k] += v[k]
    overall = metrics(agg)

    return {
        "benchmark": "OWASP Benchmark v1.2 (Java)",
        "files_scanned": len(results),
        "parse_errors": errors,
        "per_category": scored,
        "excluded_categories": excluded,
        "overall": overall,
    }


def render(r: dict) -> str:
    out = [
        "=" * 86,
        f"{r['benchmark']} — CPGuard 탐지 성능",
        "=" * 86,
        f"스캔한 파일 {r['files_scanned']}개 (파싱 오류 {r['parse_errors']}건)",
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
    if ex:
        out.append("지표 제외 (데이터 흐름 분석 대상이 아닌 설정·API 사용 점검 항목):")
        out.append("  " + ", ".join(f"{k}({v})" for k, v in ex.items()))
    out.append("")
    out.append("점수 = 재현율 - 오탐률 (OWASP Benchmark 공식 지표, 무작위 추측 = 0.000)")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="OWASP Benchmark 기반 CPGuard 탐지 성능 평가")
    ap.add_argument("root", help="BenchmarkJava 저장소 경로")
    ap.add_argument("--json", help="결과를 JSON 으로 저장")
    ap.add_argument("--limit", type=int, help="앞에서 N개만 (빠른 확인용)")
    ap.add_argument("--workers", type=int, help="병렬 프로세스 수")
    args = ap.parse_args()

    result = evaluate(Path(args.root), args.limit, args.workers)
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
