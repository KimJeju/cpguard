"""합본 진단 결과 보고서의 데이터 모델.

여러 프로젝트를 한 건의 진단으로 묶어 발주처에 제출하는 보고서다. 실제 진단 산출물의
구성을 그대로 따른다.

    1. 취약점 진단 개요   1.1 진단 목적 / 1.2 점검 수행 일정 / 1.3 점검 도구 / 1.4 점검 수행 인원
    2. 진단 항목          유형별 항목 수 · 병행 적용 기준의 대응표
    3. 진단 결과          3.1 최초 진단 결과 / 3.2 진단 결과 점검(정오탐) / 3.3 최종 점검 결과
                          3.3.x 프로젝트별 상세

핵심은 **최초 검출과 최종 조치대상을 나눠 싣는 것**이다. 정적 분석 결과를 그대로 내면
발주처가 받아들이지 못한다. 진단원이 소스 컨텍스트를 보고 오탐·제외로 판정한 근거를
함께 실어야 산출물이 된다. CPGuard 는 검토 화면의 감사 상태가 그 판정에 해당하므로,
여기서 그대로 읽어 쓴다.

    취약 확정(confirmed) · 미확인       -> 조치대상
    오탐(false_positive)               -> 오탐
    보류(deferred)                     -> 제외
    조치완료(fixed)                    -> 조치완료(최종 집계에서 빠진다)

렌더러(pdf/word)는 이 모듈이 만든 dict 를 표로 옮기기만 한다 — 두 포맷이 같은 숫자를
내도록 계산을 한 군데 둔다.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from .. import standards as _sm
from .pdf import SEV_ORDER

#: 감사 상태 -> 산출물의 '사유'. 미확인은 아직 판정 전이므로 조치대상으로 남긴다.
AUDIT_REASON = {"false_positive": "오탐", "deferred": "제외", "fixed": "조치완료"}
AUDIT_REASON_EN = {"false_positive": "False positive", "deferred": "Excluded", "fixed": "Fixed"}

#: 행안부 유형별 설명 — 참조 산출물의 '2. 진단 항목' 표에 들어가는 문안.
GROUP_DESC = {
    "입력데이터 검증 및 표현": (
        "프로그램 입력값에 대한 검증 누락 또는 부적절한 검증, 데이터의 잘못된 형식 지정으로 "
        "발생할 수 있는 보안약점",
        "Weaknesses arising from missing or improper validation of program input, or from "
        "incorrect data formatting."),
    "보안기능": (
        "보안기능(인증, 접근제어, 기밀성 등)을 부적절하게 구현 시 발생할 수 있는 보안약점",
        "Weaknesses arising from improperly implemented security functions (authentication, "
        "access control, confidentiality, and so on)."),
    "시간 및 상태": (
        "동시 또는 거의 동시 수행하는 병렬 시스템, 하나 이상의 프로세스가 동작하는 환경에서 "
        "시간 및 상태를 부적절하게 관리하여 발생할 수 있는 보안약점",
        "Weaknesses arising from improper management of time and state in concurrent or "
        "multi-process environments."),
    "에러처리": (
        "에러를 처리하지 않거나 불충분하게 처리하여 에러 정보에 중요정보가 포함될 때 발생할 수 "
        "있는 보안약점",
        "Weaknesses arising when errors are unhandled or insufficiently handled and error "
        "information carries sensitive data."),
    "코드오류": (
        "타입변환 오류, 자원(메모리 등)의 부적절한 반환 등과 같이 개발자가 범할 수 있는 코딩 "
        "오류로 인해 유발되는 보안약점",
        "Weaknesses caused by developer coding errors such as type-conversion faults or "
        "improper resource release."),
    "캡슐화": (
        "중요한 데이터 또는 기능성을 불충분하게 캡슐화하였을 때, 인가되지 않은 사용자에게 데이터 "
        "누출이 가능해지는 보안약점",
        "Weaknesses that let data leak to unauthorised users when important data or "
        "functionality is insufficiently encapsulated."),
    "API 오용": (
        "의도된 사용에 반하는 방법으로 API 를 사용하거나, 보안에 취약한 API 를 사용하여 발생할 수 "
        "있는 보안약점",
        "Weaknesses arising from using an API contrary to its intended use, or from using an "
        "API that is inherently insecure."),
    "웹 취약점": (
        "전자금융감독규정에 근거해 웹·모바일·HTS 서비스에 병행 적용하는 취약점 점검 항목",
        "Web / mobile / HTS checks applied in parallel under the Electronic Financial "
        "Supervision Regulation."),
}

LANG_LABEL = {
    "javascript": "JavaScript", "typescript": "TypeScript", "php": "PHP", "python": "Python",
    "java": "Java", "kotlin": "Kotlin", "go": "Go", "ruby": "Ruby", "cpp": "C++", "c": "C",
    "swift": "Swift", "csharp": "C#",
}


@dataclass
class ProjectRow:
    """3.1 / 3.3 표의 한 줄 = 프로젝트 하나."""
    scan: object
    name: str
    files: int
    lines: int
    languages: str
    total: int                                   # 검출(또는 조치대상) 건수
    sev: dict[str, int] = field(default_factory=dict)
    weaknesses: list[dict] = field(default_factory=list)   # 3.3.x 상세 표


def _sev_counts(findings) -> dict[str, int]:
    out = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = f.get("severity")
        if s in out:
            out[s] += 1
    return out


def _weakness_name(f, stds, lang: str) -> tuple[str, str, str]:
    """(분류, 유형, 보안약점명) — 기준 표에 대응시킨다. 어디에도 없으면 규칙 id 로 적는다."""
    en = lang == "en"
    cwe = (f.get("cwe") or "").strip().upper()
    for std in stds:
        it = std.item_for(cwe)
        if it:
            return ((std.name_en if en else std.name),
                    (it.group_en if en else it.group),
                    (it.name_en if en else it.name))
    return ("-", "-", f.get("rule_id", "-"))


def build(scans, standards: list[str] | str | None = None, lang: str = "ko") -> dict:
    """합본 보고서에 필요한 모든 표를 미리 계산한다.

    scans: Scan 객체들(최신순으로 받는다). 각각이 보고서의 한 '서비스'가 된다.
    """
    en = lang == "en"
    ids = [standards] if isinstance(standards, str) else list(standards or [])
    stds = [s for s in (_sm.get(i) for i in ids) if s]
    reason_map = AUDIT_REASON_EN if en else AUDIT_REASON

    initial: list[ProjectRow] = []
    final: list[ProjectRow] = []
    review: dict[tuple, dict] = {}          # 3.2 정오탐 표 (보안약점명, 위험도, 사유) -> 집계
    all_cwe: Counter = Counter()

    for scan in scans:
        findings = scan.findings
        audit = scan.audit or {}
        name = scan.project or Path(scan.name).stem
        langs = ", ".join(LANG_LABEL.get(x, x) for x in scan.language_list) or "-"

        kept, dropped = [], []
        for i, f in enumerate(findings):
            state = audit.get(str(i), "")
            (dropped if state in reason_map else kept).append((f, state))

        initial.append(ProjectRow(
            scan=scan, name=name, files=scan.file_count, lines=scan.code_lines,
            languages=langs, total=len(findings), sev=_sev_counts(findings)))

        # 3.2 — 진단원이 조치대상에서 뺀 항목과 그 사유
        notes = scan.audit_notes or {}
        for f, state in dropped:
            _cls, _grp, wname = _weakness_name(f, stds, lang)
            key = (wname, f.get("severity", ""), reason_map[state])
            row = review.setdefault(key, {"name": wname, "severity": f.get("severity", ""),
                                          "reason": reason_map[state], "n": 0,
                                          "opinion": "", "project": name})
            row["n"] += 1
            if not row["opinion"]:
                idx = findings.index(f)
                row["opinion"] = (notes.get(str(idx)) or "").strip()

        # 3.3 — 조치대상 기준
        kf = [f for f, _s in kept]
        by_weak: dict[tuple, dict] = {}
        for f in kf:
            cls, grp, wname = _weakness_name(f, stds, lang)
            k = (cls, grp, wname, f.get("severity", ""))
            d = by_weak.setdefault(k, {"cls": cls, "group": grp, "name": wname,
                                       "severity": f.get("severity", ""), "n": 0})
            d["n"] += 1
            if c := (f.get("cwe") or "").strip().upper():
                all_cwe[c] += 1
        order = {s: i for i, s in enumerate(SEV_ORDER)}
        final.append(ProjectRow(
            scan=scan, name=name, files=scan.file_count, lines=scan.code_lines,
            languages=langs, total=len(kf), sev=_sev_counts(kf),
            weaknesses=sorted(by_weak.values(),
                              key=lambda d: (order.get(d["severity"], 9), -d["n"]))))

    def totals(rows):
        agg = {s: 0 for s in SEV_ORDER}
        for r in rows:
            for s in SEV_ORDER:
                agg[s] += r.sev.get(s, 0)
        return {"files": sum(r.files for r in rows), "lines": sum(r.lines for r in rows),
                "total": sum(r.total for r in rows), "sev": agg}

    # 2. 진단 항목 — 기준별 유형과 항목 수. GROUP_DESC 는 한국어 유형명이 키다.
    groups = []
    for std in stds:
        seen = Counter(it.group for it in std.items)
        for ko_group, n in seen.items():
            en_group = next(x.group_en for x in std.items if x.group == ko_group)
            desc = GROUP_DESC.get(ko_group, ("", ""))
            groups.append({"standard": std.name_en if en else std.name,
                           "group": en_group if en else ko_group,
                           "desc": desc[1] if en else desc[0], "n": n})

    return {
        "standards": stds,
        "initial": initial, "initial_total": totals(initial),
        "final": final, "final_total": totals(final),
        "review": sorted(review.values(), key=lambda d: -d["n"]),
        "review_total": sum(d["n"] for d in review.values()),
        "groups": groups,
        "cwe_counts": all_cwe,
        "projects": len(list(scans)),
    }
