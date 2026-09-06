"""SARIF 2.1.0 직렬화.

데이터 흐름 트레이스를 codeFlows/threadFlows 에 그대로 싣는다.
이 포맷이 외부 도구(IDE·CI)와 후속 레이어(LLM 트리아지·웹 대시보드)의 공통 계약이다.
"""
from __future__ import annotations

import json
from pathlib import Path

from .finding import Finding

_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def _location(step, base: Path | None):
    from ..extract import strip_longpath
    uri = strip_longpath(step.loc.file)   # Windows 긴 경로 탐색용 \\?\ 접두 제거
    if base is not None:
        try:
            uri = str(Path(uri).resolve().relative_to(Path(strip_longpath(base)))).replace("\\", "/")
        except Exception:
            uri = Path(uri).name
    # SARIF 는 1-based 행번호만 받는다. 파일명 규칙처럼 줄이 없는 탐지는 Loc 이 0 이라
    # 그대로 내보내면 GitHub 이 파일 전체를 거부한다 — 탐지 한 건 때문에 결과가 통째로
    # 사라지므로 여기서 올려 맞춘다(실제로 Code Scanning 업로드가 이걸로 실패했다).
    start = max(1, step.loc.start_line)
    end = max(start, step.loc.end_line)
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {
                "startLine": start,
                "startColumn": step.loc.start_col + 1,
                "endLine": end,
                "endColumn": step.loc.end_col + 1,
                "snippet": {"text": step.code},
            },
        },
        "message": {"text": f"{step.kind}: {step.code}"},
    }


def to_sarif(findings: list[Finding], base: str | Path | None = None) -> dict:
    base_path = Path(base).resolve() if base else None

    rules, seen = [], {}
    for f in findings:
        if f.rule_id in seen:
            continue
        seen[f.rule_id] = len(rules)
        rules.append({
            "id": f.rule_id,
            "shortDescription": {"text": f.message},
            "properties": {"cwe": f.cwe, "owasp": f.owasp, "severity": f.severity,
                           "tags": [t for t in (f.cwe, f.owasp) if t]},
            "defaultConfiguration": {"level": _LEVEL.get(f.severity, "warning")},
        })

    results = []
    for f in findings:
        results.append({
            "ruleId": f.rule_id,
            "ruleIndex": seen[f.rule_id],
            "level": _LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [_location(f.sink, base_path)],
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [{"location": _location(s, base_path)} for s in f.steps]
                }]
            }],
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "CPGuard", "informationUri": "https://github.com/KimJeju/cpguard", "rules": rules}},
            "results": results,
        }],
    }


def dump(findings: list[Finding], path: str | Path, base: str | Path | None = None) -> None:
    Path(path).write_text(json.dumps(to_sarif(findings, base), indent=2, ensure_ascii=False), encoding="utf-8")
