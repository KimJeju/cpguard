"""DVWA 기반 탐지 성능 평가.

DVWA(Damn Vulnerable Web Application)는 취약점 모듈마다 보안 수준별 소스를 함께 제공한다.
  vulnerabilities/<모듈>/source/low.php        - 의도적으로 취약 (탐지해야 정답)
  vulnerabilities/<모듈>/source/impossible.php - 제대로 방어      (탐지하면 오탐)
이 쌍이 라벨링된 정답지 역할을 하므로, 재현율과 오탐률을 실제 수치로 측정할 수 있다.

medium/high 는 부분 방어(우회 가능)라 정답이 모호해 기본 지표에서 제외하고 참고로만 센다.

사용:
    python bench/dvwa_eval.py <DVWA 경로> [--json out.json]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cpguard.parse import loader, normalize  # noqa: E402
from cpguard.scanner import scan_file, scan_path  # noqa: E402
from cpguard.taint import engine  # noqa: E402
from cpguard.taint.spec import load_rules  # noqa: E402

# 우리 규칙이 다루는 취약점 유형에 해당하는 DVWA 모듈.
# 나머지(브루트포스·CSRF·캡차 등)는 정적 데이터흐름 분석의 대상이 아니라 별도로 표시한다.
COVERED = {
    "sqli": "php.sqli",
    "sqli_blind": "php.sqli",
    "exec": "php.command-injection",
    "xss_r": "php.xss",
    "xss_s": "php.xss",
    "xss_d": "php.xss",
    "fi": "php.file-inclusion",
    "upload": "php.file-inclusion",
    "open_redirect": "php.open-redirect",
    "javascript": "php.xss",
}


def has_sink(path: Path, rules) -> bool:
    """이 파일 안에 규칙이 정의한 위험 지점 호출이 하나라도 있는가.

    DVWA 의 source/*.php 는 조각이라 위험 지점이 부모 페이지에 있는 경우가 많다.
    조각 안에 sink 자체가 없으면 어떤 데이터흐름 분석기도 원리상 탐지할 수 없으므로,
    재현율 계산에서 제외해야 측정이 정직해진다.
    """
    try:
        src = path.read_bytes()
        tree = loader.parse_source(src, language="php")
        module = normalize.normalize(tree, file=str(path), language="php")
    except Exception:
        return False

    def walk(nodes):
        for n in nodes:
            yield n
            for attr in ("body", "then", "orelse", "children", "args"):
                sub = getattr(n, attr, None)
                if isinstance(sub, list):
                    yield from walk(sub)
            for attr in ("value", "target", "callee", "obj", "test"):
                sub = getattr(n, attr, None)
                if sub is not None and not isinstance(sub, (str, int, float)):
                    yield from walk([sub])

    for node in walk(module.body):
        callee = getattr(node, "callee", None)
        if callee is None:
            continue
        cp = engine.path_of(callee)
        if cp and any(engine._sink_for(cp, r) for r in rules):
            return True
    return False


def scan(path: Path, rules) -> list[str]:
    try:
        return sorted({f.rule_id for f in scan_file(path, rules)})
    except Exception as e:  # 파싱 실패도 결과로 남긴다
        return [f"<error:{type(e).__name__}>"]


def evaluate(dvwa: Path) -> dict:
    rules = load_rules()
    vuln_dir = dvwa / "vulnerabilities"
    if not vuln_dir.is_dir():
        raise SystemExit(f"DVWA 경로가 아닙니다(vulnerabilities 없음): {dvwa}")

    rows = []
    for module_dir in sorted(p for p in vuln_dir.iterdir() if p.is_dir()):
        src = module_dir / "source"
        if not src.is_dir():
            continue
        row = {"module": module_dir.name, "covered": module_dir.name in COVERED}
        low_file = src / "low.php"
        row["measurable"] = low_file.is_file() and has_sink(low_file, rules)
        for level in ("low", "medium", "high", "impossible"):
            f = src / f"{level}.php"
            row[level] = scan(f, rules) if f.is_file() else None
        rows.append(row)

    covered = [r for r in rows if r["covered"] and r["measurable"]]
    unmeasurable = [r["module"] for r in rows if r["covered"] and not r["measurable"]]
    tp = sum(1 for r in covered if r["low"])                     # 취약을 잡음
    fn = sum(1 for r in covered if r["low"] == [])               # 취약을 놓침
    fp = sum(1 for r in covered if r["impossible"])              # 안전을 잘못 잡음
    tn = sum(1 for r in covered if r["impossible"] == [])        # 안전을 통과시킴

    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0

    # 참고: 부분 방어 레벨에서의 탐지 (정답 모호)
    partial = {
        lvl: sum(1 for r in covered if r[lvl]) for lvl in ("medium", "high")
    }

    return {
        "rows": rows,
        "unmeasurable": unmeasurable,
        "metrics": {
            "modules_covered": len(covered), "modules_total": len(rows),
            "TP": tp, "FN": fn, "FP": fp, "TN": tn,
            "recall": recall, "precision": precision, "f1": f1,
            "false_positive_rate": fp_rate,
        },
        "partial_levels": partial,
    }


def render(result: dict) -> str:
    m = result["metrics"]
    out = []
    out.append("=" * 78)
    out.append("DVWA 탐지 성능 평가  (low=취약/탐지해야 함, impossible=안전/탐지하면 오탐)")
    out.append("=" * 78)
    hdr = f"{'모듈':<16}{'대상':<6}{'low':<26}{'impossible':<24}{'판정'}"
    out.append(hdr)
    out.append("-" * 78)

    for r in result["rows"]:
        if not r["covered"] or not r.get("measurable"):
            continue
        low = ",".join(r["low"] or []) or "-"
        imp = ",".join(r["impossible"] or []) or "-"
        ok_low = "O" if r["low"] else "X(미탐)"
        ok_imp = "O" if r["impossible"] == [] else "X(오탐)"
        out.append(f"{r['module']:<16}{'예':<6}{low[:24]:<26}{imp[:22]:<24}{ok_low}/{ok_imp}")

    out.append("")
    um = result.get("unmeasurable", [])
    if um:
        out.append(f"측정 제외({len(um)}개) - 조각 안에 위험 지점이 없어 원리상 탐지 불가: {', '.join(um)}")
        out.append("  (DVWA source/*.php 는 발췌 조각이고, 출력·include 는 부모 페이지에 있다)")
    skipped = [r["module"] for r in result["rows"] if not r["covered"]]
    out.append(f"규칙 미대상 모듈({len(skipped)}개, 데이터흐름 분석 범위 밖): {', '.join(skipped)}")
    out.append("")
    out.append("-" * 78)
    out.append(f"대상 모듈 {m['modules_covered']} / 전체 {m['modules_total']}")
    out.append(f"TP {m['TP']}  FN {m['FN']}  FP {m['FP']}  TN {m['TN']}")
    out.append(f"재현율(Recall)   : {m['recall']:.1%}   (취약 코드를 잡아낸 비율)")
    out.append(f"정밀도(Precision): {m['precision']:.1%}   (탐지 중 실제 취약 비율)")
    out.append(f"F1               : {m['f1']:.3f}")
    out.append(f"오탐률           : {m['false_positive_rate']:.1%}   (안전 코드를 잘못 잡은 비율)")
    p = result["partial_levels"]
    out.append(f"참고 - 부분방어 레벨 탐지: medium {p['medium']}건, high {p['high']}건")
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="DVWA 기반 CPGuard 탐지 성능 평가")
    ap.add_argument("dvwa", help="DVWA 소스 루트 경로")
    ap.add_argument("--json", help="결과를 JSON 으로 저장")
    args = ap.parse_args()

    dvwa = Path(args.dvwa)
    result = evaluate(dvwa)
    print(render(result))

    findings, report = scan_path(dvwa)
    by_rule: dict[str, int] = {}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    print()
    print("=" * 78)
    print("전체 프로젝트 스캔 (DVWA 전체, 파일 경계 넘는 분석 포함)")
    print("=" * 78)
    print(report.summary())
    print(f"탐지 {len(findings)}건")
    for rid, n in sorted(by_rule.items(), key=lambda x: -x[1]):
        print(f"  {rid:<28} {n}건")
    result["project_scan"] = {"total": len(findings), "by_rule": by_rule,
                              "scanned": report.scanned, "partial": len(report.partial)}
    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=2, ensure_ascii=False),
                                   encoding="utf-8")
        print(f"\nJSON 저장: {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
