#!/usr/bin/env python3
"""SARIF → GitHub Step Summary(마크다운). 등급별 집계 + 상위 항목.

stdlib 만 사용. 인자: SARIF 파일 경로. 표준출력으로 마크다운.
"""
import json
import sys
from collections import Counter

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8")  # Windows cp949 등에서 이모지 출력 보장
    except (AttributeError, ValueError):
        pass

ORDER = ["critical", "high", "medium", "low", "info"]
ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def main(path: str) -> int:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"## 🛡️ CPGuard SAST\n\nSARIF 읽기 실패: `{e}`")
        return 0

    by_sev: Counter = Counter()
    by_rule: Counter = Counter()
    for run in data.get("runs", []):
        for r in run.get("results", []):
            sev = (r.get("properties", {}) or {}).get("severity", "").lower()
            if sev not in ORDER:
                # SARIF level 로 폴백
                sev = {"error": "high", "warning": "medium", "note": "low"}.get(
                    r.get("level", "warning"), "medium")
            by_sev[sev] += 1
            by_rule[r.get("ruleId", "?")] += 1

    total = sum(by_sev.values())
    out = ["## 🛡️ CPGuard SAST", ""]
    if total == 0:
        out.append("탐지된 취약점 없음. ✅")
        print("\n".join(out))
        return 0

    out.append(f"총 **{total}**건 탐지")
    out.append("")
    out.append("| 등급 | 건수 |")
    out.append("|---|---:|")
    for sev in ORDER:
        if by_sev.get(sev):
            out.append(f"| {ICON[sev]} {sev} | {by_sev[sev]} |")
    out.append("")
    out.append("<details><summary>룰별 상위 10</summary>\n")
    out.append("| 룰 | 건수 |")
    out.append("|---|---:|")
    for rule, n in by_rule.most_common(10):
        out.append(f"| `{rule}` | {n} |")
    out.append("\n</details>")
    print("\n".join(out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "cpguard.sarif"))
