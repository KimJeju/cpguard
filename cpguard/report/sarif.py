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
    uri = step.loc.file
    if base is not None:
        try:
            uri = str(Path(step.loc.file).resolve().relative_to(base)).replace("\\", "/")
        except Exception:
            uri = Path(step.loc.file).name
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": uri},
            "region": {
                "startLine": step.loc.start_line,
                "startColumn": step.loc.start_col + 1,
                "endLine": step.loc.end_line,
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
            "properties": {"cwe": f.cwe, "severity": f.severity},
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
