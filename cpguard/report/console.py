"""콘솔 출력 — source→sink 경로를 사람이 읽게."""
from __future__ import annotations

from pathlib import Path

from .finding import Finding

_MARK = {"critical": "!!", "high": "!", "medium": "-", "low": ".", "info": "."}
_VERDICT = {"true_positive": "실제 취약", "false_positive": "오탐", "uncertain": "판단보류"}


def _rel(p: str, base) -> str:
    if not base:
        return p
    try:
        return str(Path(p).resolve().relative_to(Path(base).resolve())).replace("\\", "/")
    except Exception:
        return Path(p).name


def render(findings: list[Finding], base=None) -> str:
    if not findings:
        return "취약점 없음 (0 findings)"

    lines: list[str] = []
    for i, f in enumerate(findings, 1):
        head = f"[{i}] {_MARK.get(f.severity,'-')} {f.severity.upper()}  {f.rule_id}  ({f.cwe})"
        if f.verdict:
            head += f"   [LLM: {_VERDICT.get(f.verdict, f.verdict)}]"
        lines.append(head)
        lines.append(f"    {f.message}")
        if f.triage_reason:
            lines.append(f"    LLM 판정 근거: {f.triage_reason}")
        for s in f.steps:
            loc = f"{_rel(s.loc.file, base)}:{s.loc.start_line}"
            lines.append(f"      {s.kind:<12} {loc:<28} {s.code}")
        lines.append("")

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    summary = ", ".join(f"{k} {v}" for k, v in sorted(by_sev.items()))
    lines.append(f"총 {len(findings)}건 ({summary})")
    return "\n".join(lines)
