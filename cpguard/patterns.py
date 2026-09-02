"""패턴 규칙 엔진 — 데이터 흐름이 필요 없는 단일 지점 점검.

taint 엔진은 "입력이 위험 지점까지 흐르는가"를 본다. 실무에서 비중이 큰 상당수 결함은
흐름과 무관한 단일 지점 사실이다 — 하드코딩된 비밀정보, 개인정보 노출, 취약한 알고리즘,
남은 디버그 코드. 이런 것은 정규식 한 줄이면 잡히므로 축을 분리했다.

이 엔진은 세 가지를 더 안다(사용자가 현장에서 만들어 쓰던 점검 스크립트에서 가져옴).
  - 검증기(validator): 정규식만으로는 오탐이 큰 형식(주민번호·카드번호)을 체크섬으로 확정한다.
  - 마스킹(mask): 탐지값을 결과에 그대로 남기면 산출물 자체가 유출원이 된다. 결과는 마스킹한다.
  - 오탐 힌트(fp_hint): 같은 줄에 process.env / example / ${...} 같은 신호가 있으면
    제외하지는 않되 신뢰도를 낮추고 표시한다 — 사람이 걸러낼 수 있게.

규칙은 cpguard/patterns/*.yml 에 데이터로 둔다. 결과는 taint 와 같은 Finding 이다.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .ir import Loc
from .report.finding import Finding, Step

PATTERN_DIR = Path(__file__).resolve().parent / "patterns"

_COMMENT_LINE = re.compile(r"^\s*(//|#|\*|/\*|<!--)")
MAX_LINE_CHARS = 5000  # 난독화/미니파이 한 줄 폭탄 방지

# 같은 줄에 있으면 오탐 가능성이 높은 신호. 제외하지 않고 신뢰도만 낮춘다.
FP_HINT = re.compile(
    r"(example|sample|dummy|changeme|change_me|placeholder|your[_-]?|xxxx+|\byyy+\b|"
    r"test123|\bfoo\b|\bbar\b|\{\{|\$\{|<%|%>|process\.env|os\.getenv|os\.environ|"
    r"System\.getenv|import\.meta\.env|ConfigurationManager|@Value\(|#\{|"
    r"\bnull\b|\bnone\b|\bundefined\b|\*\*\*\*)", re.IGNORECASE)

# 파일명·확장자 자체가 위험한 경우 (내용을 읽지 않고도 판정)
RISKY_FILENAMES = re.compile(
    r"(?i)(^\.env(\..+)?$|^id_(rsa|dsa|ecdsa|ed25519)$|^\.npmrc$|^\.pypirc$|^\.netrc$|"
    r"^\.htpasswd$|^kubeconfig$|^credentials$|^secrets?\.(ya?ml|json|properties)$|"
    r"\.(pem|key|p12|pfx|jks|keystore|ppk|asc|ovpn|kdbx)$|"
    r"\.(bak|old|orig|save|swp|swo|copy|backup)$|"
    r"^web\.config$|^local\.settings\.json$|^terraform\.tfstate(\.backup)?$|"
    r"^database\.ya?ml$|^wp-config\.php$|^\.dockercfg$|^\.bash_history$)")


# ---------- 검증기: 정규식이 잡은 후보를 체크섬으로 확정 ----------

def _rrn_ok(value: str) -> bool:
    """주민등록번호: 13자리, 생년월일 범위, 가중치 체크섬."""
    d = re.sub(r"\D", "", value)
    if len(d) != 13:
        return False
    mm, dd = int(d[2:4]), int(d[4:6])
    if not (1 <= mm <= 12 and 1 <= dd <= 31):
        return False
    w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    s = sum(int(d[i]) * w[i] for i in range(12))
    return (11 - (s % 11)) % 10 == int(d[12])


def _luhn_ok(value: str) -> bool:
    d = re.sub(r"\D", "", value)
    if not (13 <= len(d) <= 19):
        return False
    total, alt = 0, False
    for ch in reversed(d):
        n = int(ch)
        if alt:
            n *= 2
            if n > 9:
                n -= 9
        total += n
        alt = not alt
    return total % 10 == 0


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = float(len(s))
    return -sum((c / n) * math.log(c / n, 2) for c in freq.values())


def _entropy_b64(value: str) -> bool:
    return _shannon(value) >= 4.5


def _entropy_hex(value: str) -> bool:
    return _shannon(value) >= 3.0


VALIDATORS = {
    "rrn": _rrn_ok,
    "luhn": _luhn_ok,
    "entropy_b64": _entropy_b64,
    "entropy_hex": _entropy_hex,
}


# ---------- 마스킹: 산출물이 유출원이 되지 않도록 ----------

def _mask_rrn(v: str) -> str:
    d = re.sub(r"\D", "", v)
    return f"{d[:6]}-{d[6]}******" if len(d) == 13 else _mask_generic(v)


def _mask_phone(v: str) -> str:
    d = re.sub(r"\D", "", v)
    return f"{d[:3]}-****-{d[-4:]}" if len(d) >= 8 else _mask_generic(v)


def _mask_email(v: str) -> str:
    if "@" not in v:
        return _mask_generic(v)
    loc, dom = v.split("@", 1)
    loc = loc[:2] + "***" if len(loc) > 2 else loc[:1] + "**"
    return f"{loc}@{dom}"


def _mask_card(v: str) -> str:
    d = re.sub(r"\D", "", v)
    return f"{d[:4]}-****-****-{d[-4:]}" if len(d) >= 12 else _mask_generic(v)


def _mask_generic(v: str) -> str:
    v = v.strip()
    if len(v) <= 6:
        return v[:1] + "*" * (len(v) - 1)
    return v[:4] + "*" * min(12, len(v) - 6) + v[-2:]


MASKERS = {
    "rrn": _mask_rrn, "phone": _mask_phone, "email": _mask_email,
    "card": _mask_card, "secret": _mask_generic, "generic": _mask_generic,
    "none": lambda v: v,
}

CONFIDENCE_ORDER = {"high": 0, "medium": 1, "low": 2}


def _lower_confidence(c: str) -> str:
    return {"high": "medium", "medium": "low"}.get(c, "low")


# ---------- 규칙 ----------

@dataclass
class PatternRule:
    id: str
    message: str
    severity: str
    cwe: str
    owasp: str
    category: str                      # secret | pii | config | hygiene | infra
    languages: list[str]               # 비어 있으면 언어 무관
    regex: re.Pattern
    excludes: list[re.Pattern] = field(default_factory=list)
    skip_comments: bool = True
    validator: str | None = None       # VALIDATORS 키
    mask: str = "none"                 # MASKERS 키
    confidence: str = "medium"         # 기본 신뢰도
    all_files: bool = False            # True 면 언어 무관 모든 텍스트 파일에 적용
    group: int = 0                     # 검증/마스킹에 쓸 캡처 그룹 (0=전체)
    file_exts: list[str] = field(default_factory=list)  # 비어 있으면 전체, 있으면 그 확장자만


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
        defaults = d.get("defaults", {})
        for entry in d.get("rules", []):
            e = {**defaults, **entry}
            rules.append(PatternRule(
                id=e["id"],
                message=e.get("message", e["id"]),
                severity=e.get("severity", "medium"),
                cwe=e.get("cwe", ""),
                owasp=e.get("owasp", ""),
                category=e.get("category", "hygiene"),
                languages=list(e.get("languages", [])),
                regex=_compile(e["pattern"]),
                excludes=[_compile(x) for x in e.get("exclude", [])],
                skip_comments=e.get("skip_comments", True),
                validator=e.get("validator"),
                mask=e.get("mask", "none"),
                confidence=e.get("confidence", "medium"),
                all_files=bool(e.get("all_files", False)),
                group=int(e.get("group", 0)),
                file_exts=[x.lower() for x in e.get("file_exts", [])],
            ))
    if language:
        rules = [r for r in rules if not r.languages or language in r.languages]
    return rules


def rules_for(rules: list[PatternRule], language: str | None,
              ext: str | None = None) -> list[PatternRule]:
    """이 파일에 적용할 규칙.

    - 언어를 아는 소스 파일: 그 언어 규칙 + 언어무관 규칙
    - 언어를 모르는 텍스트 파일: all_files 규칙만
    - file_exts 가 지정된 규칙은 그 확장자에서만 (예: 설정파일 전용 자격증명 규칙)
    """
    ext = (ext or "").lower()
    if language:
        cand = [r for r in rules if not r.languages or language in r.languages]
    else:
        cand = [r for r in rules if r.all_files and not r.languages]
    return [r for r in cand if not r.file_exts or ext in r.file_exts]


# ---------- 스캔 ----------

def _emit(rule: PatternRule, file: str, line_no: int, col: int, end: int,
          snippet: str, value: str, fp_hint: bool) -> Finding:
    conf = _lower_confidence(rule.confidence) if fp_hint else rule.confidence
    loc = Loc(file=file, start_line=line_no, start_col=col, end_line=line_no,
              end_col=end, start_byte=0, end_byte=0)
    return Finding(
        rule_id=rule.id, message=rule.message, severity=rule.severity,
        cwe=rule.cwe, owasp=rule.owasp,
        steps=[Step("match", loc, snippet)],
        precision=conf, fp_hint=fp_hint, matched_value=value, category=rule.category,
    )


def _masked_line(line: str, value: str, masked: str) -> str:
    out = line.strip()
    if value and masked != value:
        out = out.replace(value, masked)
    if len(out) > 200:
        out = out[:200] + "…"
    return out


def scan_text(src: str, file: str, rules: list[PatternRule]) -> list[Finding]:
    """소스 텍스트를 줄 단위로 훑어 패턴 규칙을 적용한다."""
    findings: list[Finding] = []
    lines = src.splitlines()
    for i, raw in enumerate(lines, 1):
        line = raw if len(raw) <= MAX_LINE_CHARS else raw[:MAX_LINE_CHARS]
        is_comment = bool(_COMMENT_LINE.match(line))
        fp = bool(FP_HINT.search(line))
        seen: set[tuple[str, str]] = set()
        for rule in rules:
            if rule.skip_comments and is_comment:
                continue
            for m in rule.regex.finditer(line):
                value = m.group(rule.group) if rule.group else m.group(0)
                key = (rule.id, value)
                if key in seen:
                    continue
                seen.add(key)
                if any(x.search(line) for x in rule.excludes):
                    continue
                if rule.validator and not VALIDATORS[rule.validator](value):
                    continue
                masked = MASKERS.get(rule.mask, MASKERS["none"])(value)
                findings.append(_emit(rule, file, i, m.start(), m.end(),
                                      _masked_line(line, value, masked), masked, fp))
                if rule.mask == "none":
                    break  # 같은 규칙은 줄당 1건이면 충분 (값을 안 남기는 규칙)
    return findings


def scan_filename(path: str | Path, file_label: str | None = None) -> Finding | None:
    """파일명·확장자 자체가 위험한 경우 (.env, id_rsa, *.pem, *.bak ...)."""
    name = Path(path).name
    if not RISKY_FILENAMES.search(name):
        return None
    loc = Loc(file=file_label or str(path), start_line=0, start_col=0, end_line=0,
              end_col=0, start_byte=0, end_byte=0)
    return Finding(
        rule_id="secret.risky-filename",
        message="민감한 파일명/확장자입니다 — 저장소에 있으면 안 되는 파일일 수 있습니다.",
        severity="high", cwe="CWE-538",
        owasp="A05:2021-Security Misconfiguration",
        steps=[Step("match", loc, name)],
        precision="medium", fp_hint=False, matched_value=name, category="secret",
    )


# ---------- 텍스트 파일 판별 (패턴 축은 언어 무관 모든 텍스트 파일을 본다) ----------

SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp", ".tif",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".mkv", ".flv",
    ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2", ".xz", ".jar", ".war", ".ear",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".dat", ".o", ".a", ".pyc", ".class",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".hwp", ".hwpx",
    ".ttf", ".otf", ".woff", ".woff2", ".eot", ".db", ".sqlite", ".mdb", ".iso",
    ".img", ".dmg", ".lock", ".map",
}
_SKIP_NAME = re.compile(r"(\.min\.(js|css)$|package-lock\.json$|yarn\.lock$|"
                        r"pnpm-lock\.yaml$|composer\.lock$|go\.sum$)", re.IGNORECASE)


def is_text_candidate(path: Path) -> bool:
    if path.suffix.lower() in SKIP_EXTS or _SKIP_NAME.search(path.name):
        return False
    try:
        with open(path, "rb") as f:
            return b"\x00" not in f.read(4096)
    except OSError:
        return False


def read_text_lenient(path: Path) -> str:
    """BOM → UTF-8 → CP949 → latin-1 순으로 시도. 현장 소스는 인코딩이 섞여 있다."""
    data = path.read_bytes()
    for enc in ("utf-8-sig", "utf-8", "cp949", "latin-1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")
