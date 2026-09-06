"""Semgrep 결과를 CPGuard 와 같은 기준으로 채점한다.

정확도 주장은 비교군이 있어야 의미가 있다. 같은 정답지(OWASP Benchmark v1.2), 같은 대상
6개 유형, 같은 제외 규칙, 같은 점수식으로 다른 도구를 재면 숫자를 나란히 놓을 수 있다.
채점 로직은 `owasp_benchmark.py` 에서 그대로 가져다 쓴다(두 곳에 두면 어긋난다).

비교의 전제 — 둘 다 빌드 없이 소스만 보는 분석기다. Semgrep OSS 는 파일 내부(intrafile)
분석이고 CPGuard 는 파일을 넘는 프로시저간 분석이라, 이 벤치마크처럼 sink 가 다른 파일에
있는 케이스에서는 설계 차이가 그대로 점수 차이로 나타난다. 유료 Semgrep Pro 엔진의
interfile 분석은 여기 포함되지 않는다.

사용:
    semgrep scan --config p/java --json --output semgrep.json <BenchmarkJava>/…/testcode
    python bench/semgrep_eval.py semgrep.json <BenchmarkJava 경로> [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from owasp_benchmark import CATEGORY_RULE, load_expected, metrics  # noqa: E402

# Semgrep 규칙 id/메시지에서 Benchmark 유형을 알아내는 표. 규칙 id 는
# java.lang.security.audit.sqli.jdbc-sqli 처럼 유형이 경로에 드러난다.
# 목록에 없는 규칙이 뜨면 채점에서 빠지므로, 실행할 때마다 미분류 규칙을 함께 출력한다.
CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "sqli": ("sqli", "sql-injection", "sql_injection", "tainted-sql"),
    "cmdi": ("command-injection", "cmdi", "process-builder", "runtime-exec", "tainted-cmd"),
    "xss": ("xss", "cross-site-scripting", "no-direct-response-writer"),
    "pathtraver": ("path-traversal", "pathtraver", "path_traversal", "file-traversal"),
    "ldapi": ("ldap-injection", "ldapi", "ldap_injection", "tainted-ldap"),
    "xpathi": ("xpath-injection", "xpathi", "xpath_injection", "tainted-xpath"),
}


def category_of(rule_id: str) -> str | None:
    r = rule_id.lower()
    for cat, keys in CATEGORY_KEYWORDS.items():
        if any(k in r for k in keys):
            return cat
    return None


def evaluate(semgrep_json: Path, root: Path) -> dict:
    expected = load_expected(root)
    data = json.loads(semgrep_json.read_text(encoding="utf-8"))

    hits: dict[str, set[str]] = {}      # 파일 stem -> 탐지된 유형
    unmapped: dict[str, int] = {}
    for r in data.get("results", []):
        stem = Path(r.get("path", "")).stem
        if stem not in expected:
            continue
        rid = r.get("check_id", "")
        cat = category_of(rid)
        if cat is None:
            unmapped[rid] = unmapped.get(rid, 0) + 1
            continue
        hits.setdefault(stem, set()).add(cat)

    cats: dict[str, dict[str, int]] = {}
    for name, (category, real) in expected.items():
        c = cats.setdefault(category, {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "total": 0})
        c["total"] += 1
        if CATEGORY_RULE.get(category) is None:
            continue
        hit = category in hits.get(name, ())
        if real:
            c["TP" if hit else "FN"] += 1
        else:
            c["FP" if hit else "TN"] += 1

    scored = {k: metrics(v) for k, v in sorted(cats.items()) if CATEGORY_RULE.get(k)}
    agg = {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "total": 0}
    for v in scored.values():
        for k in agg:
            agg[k] += v[k]

    return {
        "benchmark": "OWASP Benchmark v1.2 (Java)",
        "tool": f"Semgrep OSS ({data.get('version', '?')}) — config p/java",
        "findings_total": len(data.get("results", [])),
        "per_category": scored,
        "overall": metrics(agg),
        "unmapped_rules": dict(sorted(unmapped.items(), key=lambda kv: -kv[1])),
    }


def render(r: dict) -> str:
    out = ["=" * 86, f"{r['benchmark']} — {r['tool']}", "=" * 86,
           f"탐지 {r['findings_total']}건 (대상 밖 규칙 포함)", ""]
    head = f"{'카테고리':<12}{'대상':>6}{'TP':>6}{'FN':>6}{'FP':>6}{'TN':>6}{'재현율':>10}{'정밀도':>10}{'F1':>8}{'오탐률':>10}{'점수':>8}"
    out += [head, "-" * 86]
    for k, v in r["per_category"].items():
        out.append(f"{k:<12}{v['total']:>6}{v['TP']:>6}{v['FN']:>6}{v['FP']:>6}{v['TN']:>6}"
                   f"{v['recall']:>9.1%}{v['precision']:>10.1%}{v['f1']:>8.3f}"
                   f"{v['false_positive_rate']:>10.1%}{v['benchmark_score']:>8.3f}")
    o = r["overall"]
    out += ["-" * 86,
            f"{'전체':<12}{o['total']:>6}{o['TP']:>6}{o['FN']:>6}{o['FP']:>6}{o['TN']:>6}"
            f"{o['recall']:>9.1%}{o['precision']:>10.1%}{o['f1']:>8.3f}"
            f"{o['false_positive_rate']:>10.1%}{o['benchmark_score']:>8.3f}", ""]
    if r["unmapped_rules"]:
        out.append("유형 매핑이 없어 채점에서 빠진 규칙(상위 10):")
        for rid, n in list(r["unmapped_rules"].items())[:10]:
            out.append(f"  {n:>5}  {rid}")
        out.append("")
    out.append("점수 = 재현율 - 오탐률 (OWASP Benchmark 공식 지표, 무작위 추측 = 0.000)")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Semgrep 결과를 CPGuard 와 같은 기준으로 채점")
    ap.add_argument("semgrep_json", help="semgrep --json 출력 파일")
    ap.add_argument("root", help="BenchmarkJava 저장소 경로(expectedresults-1.2.csv 위치)")
    ap.add_argument("--json", help="결과를 JSON 으로 저장")
    args = ap.parse_args()

    result = evaluate(Path(args.semgrep_json), Path(args.root))
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(render(result))
    if args.json:
        print(f"\nJSON 저장: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
