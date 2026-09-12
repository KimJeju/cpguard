"""도구 구현 — 코어를 호출하고 결과를 성형한다. SDK 비의존(테스트가 직접 부른다).

세션 finding 저장소가 여기 산다. stdio 서버 한 프로세스 = 한 대화이므로, 스캔으로
만든 finding 을 id→Finding 로 들고 있다가 이후 도구(evidence·explain·…)가 id 로
집어오게 한다. 서버 재시작을 넘는 영속은 MVP 밖이다(필요해지면 경량 저장소).

경계: scan 대상 경로는 실재하는 파일이어야 하고, 코드를 실행하지 않는다(파싱만).
"""
from __future__ import annotations

from pathlib import Path

from cpguard.report.finding import Finding
from cpguard.report.remediation import remediation_for

from . import render


class FindingStore:
    """id → Finding. scan 이 채우고 나머지 도구가 조회한다."""

    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}
        self._order: list[str] = []      # 삽입 순서(목록 안정성)

    def register(self, findings: list[Finding]) -> list[tuple[str, Finding]]:
        """findings 에 안정 id 를 붙여 저장하고 (id, finding) 쌍을 돌려준다."""
        used = set(self._by_id)
        out: list[tuple[str, Finding]] = []
        for f in findings:
            fid = render.finding_id(f, used)
            if fid not in self._by_id:
                self._order.append(fid)
            self._by_id[fid] = f
            out.append((fid, f))
        return out

    def get(self, fid: str) -> Finding | None:
        return self._by_id.get(fid)

    def items(self) -> list[tuple[str, Finding]]:
        return [(fid, self._by_id[fid]) for fid in self._order]


def scan_file(store: FindingStore, path: str) -> dict:
    """파일 하나를 빠르게 검사하고 요약을 돌려준다. 흐름 단계는 붙이지 않는다.

    찾은 finding 을 저장소에 등록해 이후 finding.evidence(id)·explain(id) 가 같은
    건을 가리키게 한다.
    """
    from cpguard.scanner import scan_file as core_scan_file

    p = Path(path)
    if not p.exists():
        return {"error": "not_found", "path": str(p)}
    if not p.is_file():
        return {"error": "not_a_file", "path": str(p)}

    findings = core_scan_file(p)
    registered = store.register(findings)
    counts: dict[str, int] = {}
    for _fid, f in registered:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return {
        "path": str(p),
        "total": len(registered),
        "counts": counts,
        "findings": [render.to_summary(f, fid) for fid, f in registered],
    }


def finding_list(store: FindingStore, severity: list[str] | None = None,
                 rule: str | None = None, file: str | None = None,
                 limit: int = 20, offset: int = 0) -> dict:
    """저장된 finding 을 필터·페이지로 돌려준다. 요약만(흐름 없음).

    severity: 포함할 심각도 목록. rule: rule_id 부분일치. file: 경로 부분일치.
    """
    sev = {s.lower() for s in severity} if severity else None
    rows = []
    for fid, f in store.items():
        if sev is not None and f.severity.lower() not in sev:
            continue
        if rule is not None and rule not in f.rule_id:
            continue
        if file is not None and file not in f.file:
            continue
        rows.append(render.to_summary(f, fid))

    total = len(rows)
    page = rows[offset:offset + limit]
    out = {"total": total, "offset": offset, "limit": limit, "findings": page}
    if offset + limit < total:
        out["next_offset"] = offset + limit
    return out


def finding_evidence(store: FindingStore, finding_id: str) -> dict:
    """한 finding 의 source→sink 경로. 요청한 것에만 흐름을 붙인다."""
    f = store.get(finding_id)
    if f is None:
        return {"error": "unknown_finding", "finding_id": finding_id}
    return render.to_evidence(f, finding_id)


def explain(store: FindingStore, rule_id: str | None = None,
            finding_id: str | None = None, lang: str = "ko") -> dict:
    """규칙의 설명·CWE·조치 권고·안전 예시. finding_id 또는 rule_id 로 조회.

    LLM 을 부르지 않는다 — 규칙 데이터에서 바로 나온다. 호스트가 고칠 때 쓴다.
    """
    if finding_id is not None:
        f = store.get(finding_id)
        if f is None:
            return {"error": "unknown_finding", "finding_id": finding_id}
        rule_id, cwe = f.rule_id, f.cwe
    elif rule_id is not None:
        cwe = None
    else:
        return {"error": "need_rule_or_finding"}

    rem = remediation_for(rule_id, en=(lang == "en"))
    if rem is None:
        return {"rule": rule_id, "cwe": cwe, "remediation": None,
                "note": "이 규칙 유형에 연결된 조치 권고가 없다(일반 지침 적용)."}
    return {"rule": rule_id, "cwe": cwe or rem.get("cwe"), **rem}
