"""패턴 규칙 엔진 — 데이터 흐름이 필요 없는 단일 지점 점검.

taint 엔진은 "입력이 위험 지점까지 흐르는가"를 본다. 그런데 실무에서 비중이 큰 상당수
결함은 흐름과 무관한 단일 지점 사실이다.

  - 하드코딩된 비밀정보(API 키·비밀번호)
  - 제거되지 않고 남은 디버그 코드
  - 취약한 해시/암호 알고리즘 사용
  - 인증서 검증 비활성화
  - 쿠키 보안 플래그 누락

이런 것들은 정규식 한 줄이면 잡히는데 taint 로 표현하려면 억지가 된다. 그래서 축을
분리했다. 두 엔진의 결과는 동일한 Finding 으로 합쳐져 같은 리포트에 실린다.

규칙은 cpguard/patterns/*.yml 에 데이터로 둔다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .ir import Loc
from .report.finding import Finding, Step

PATTERN_DIR = Path(__file__).resolve().parent / "patterns"

# 주석만으로 이뤄진 줄은 일부 규칙에서 제외한다(주석 속 예시 코드 오탐 방지)
_COMMENT_LINE = re.compile(r"^\s*(//|#|\*|/\*|<!--)")


@dataclass
class PatternRule:
    id: str
    message: str
    severity: str
    cwe: str
    owasp: str
    languages: list[str]
    regex: re.Pattern
    # 이 정규식이 같은 줄에서 매칭되면 해당 탐지를 취소한다(정제·예외 표현)
    excludes: list[re.Pattern] = field(default_factory=list)
    skip_comments: bool = True


def _compile(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


def load_pattern_rules(directory: str | Path | None = None,
                       language: str | None = None) -> list[PatternRule]:
    directory = Path(directory) if directory else PATTERN_DIR
    if not directory.is_dir():
        return []
    rules: list[PatternRule] = []
    for path in sorted(directory.glob("*.yml")):
        d = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for entry in d.get("rules", []):
            rules.append(PatternRule(
                id=entry["id"],
                message=entry.get("message", entry["id"]),
                severity=entry.get("severity", "medium"),
                cwe=entry.get("cwe", ""),
                owasp=entry.get("owasp", ""),
                languages=list(entry.get("languages", d.get("languages", []))),
                regex=_compile(entry["pattern"]),
                excludes=[_compile(x) for x in entry.get("exclude", [])],
                skip_comments=entry.get("skip_comments", True),
            ))
    if language:
        rules = [r for r in rules if not r.languages or language in r.languages]
    return rules


def scan_text(src: str, file: str, rules: list[PatternRule]) -> list[Finding]:
    """소스 텍스트를 줄 단위로 훑어 패턴 규칙을 적용한다."""
    findings: list[Finding] = []
    lines = src.splitlines()
    for rule in rules:
        for i, line in enumerate(lines, 1):
            if rule.skip_comments and _COMMENT_LINE.match(line):
                continue
            m = rule.regex.search(line)
            if not m:
                continue
            if any(x.search(line) for x in rule.excludes):
                continue
            snippet = line.strip()
            if len(snippet) > 200:
                snippet = snippet[:200] + "…"
            loc = Loc(file=file, start_line=i, start_col=m.start(),
                      end_line=i, end_col=m.end(), start_byte=0, end_byte=0)
            findings.append(Finding(
                rule_id=rule.id, message=rule.message, severity=rule.severity,
                cwe=rule.cwe, owasp=rule.owasp,
                steps=[Step("match", loc, snippet)],
            ))
    return findings
