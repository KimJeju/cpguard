"""도구 구현 — 코어를 호출하고 결과를 성형한다. SDK 비의존(테스트가 직접 부른다).

세션 finding 저장소가 여기 산다. stdio 서버 한 프로세스 = 한 대화이므로, 스캔으로
만든 finding 을 id→Finding 로 들고 있다가 이후 도구(evidence·explain·…)가 id 로
집어오게 한다. 서버 재시작을 넘는 영속은 MVP 밖이다(필요해지면 경량 저장소).

경계: scan 대상 경로는 실재하는 파일이어야 하고, 코드를 실행하지 않는다(파싱만).
"""
from __future__ import annotations

from pathlib import Path

from cpguard.report.finding import Finding, fingerprint
from cpguard.report.remediation import remediation_for

from . import probe, render


def _fp(f: Finding) -> str:
    """줄에 안 흔들리는 지문 — verify 가 수정 전후를 잇는다(웹 스냅샷 비교와 같은 것)."""
    return fingerprint(f.rule_id, f.file, f.sink.code or "")


class FindingStore:
    """id → Finding. scan 이 채우고 나머지 도구가 조회한다."""

    def __init__(self) -> None:
        self._by_id: dict[str, Finding] = {}
        self._order: list[str] = []      # 삽입 순서(목록 안정성)
        #: 파일(경로) → 그 파일에서 마지막으로 본 지문 집합. verify 의 baseline.
        self._seen_fp: dict[str, set[str]] = {}

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

    def snapshot_file(self, path: str, findings: list[Finding]) -> None:
        """이 파일에서 지금 본 지문 집합을 baseline 으로 기록한다(verify 대조용)."""
        self._seen_fp[str(path)] = {_fp(f) for f in findings}

    def baseline_fp(self, path: str) -> set[str] | None:
        """이 파일의 직전 지문 집합. 스캔한 적 없으면 None."""
        return self._seen_fp.get(str(path))


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
    store.snapshot_file(p, findings)          # verify 의 baseline
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


def probe_get(store: FindingStore, finding_id: str) -> dict:
    """finding 하나를 실증 탐침 + 오라클로. 발사는 에이전트, 판정은 validation.submit."""
    f = store.get(finding_id)
    if f is None:
        return {"error": "unknown_finding", "finding_id": finding_id}
    return probe.build_probe(f, finding_id)


def validation_submit(store: FindingStore, finding_id: str, observed: dict) -> dict:
    """에이전트가 발사 후 관찰한 것(observed)을 오라클과 대조해 판정한다.

    observed 키: elapsed_ms · oast_hit · body_marker · file_leak · redirect_external ·
    error_signature · status · blocked(검증불가 사유) · static_safe · agent_confirmed.
    """
    f = store.get(finding_id)
    if f is None:
        return {"error": "unknown_finding", "finding_id": finding_id}
    result = probe.judge(f, observed or {})
    return {"id": finding_id, **result}


def verify(store: FindingStore, path: str) -> dict:
    """파일을 고친 뒤 다시 스캔해 직전 상태와 대조한다 — 닫힘 / 남음 / 새로 생김.

    에이전트는 자기가 부른 정제가 흐름을 실제로 끊었는지 모른다. CPGuard 는 안다.
    지문(줄에 안 흔들림) 기준으로 비교하므로 포맷팅·줄 이동에 흔들리지 않는다.

    직전 스캔이 없으면(baseline 없음) 그냥 현재 상태를 새 baseline 으로 잡고 알린다 —
    무엇에 견줘야 할지 모르는데 '전부 새로 생김'이라 말하면 거짓이다.
    """
    from cpguard.scanner import scan_file as core_scan_file

    p = Path(path)
    if not p.exists():
        return {"error": "not_found", "path": str(p)}
    if not p.is_file():
        return {"error": "not_a_file", "path": str(p)}

    prior = store.baseline_fp(p)
    findings = core_scan_file(p)
    now = {_fp(f): f for f in findings}
    store.register(findings)
    store.snapshot_file(p, findings)          # 다음 verify 를 위해 baseline 갱신

    if prior is None:
        return {"path": str(p), "baseline": "none",
                "note": "직전 스캔이 없어 대조 불가 — 지금 상태를 baseline 으로 잡았다. "
                        "고친 뒤 다시 verify 하면 닫힘/남음을 알려준다.",
                "current": len(findings)}

    closed = prior - now.keys()               # 있다가 사라짐 = 고쳐짐
    remaining = prior & now.keys()            # 그대로 있음
    new = now.keys() - prior                  # 없다가 생김(수정이 새 결함을 만듦)

    def _row(fp: str) -> dict:
        f = now[fp]
        return {"rule": f.rule_id, "line": f.sink.loc.start_line, "sink": f.sink.code}

    return {
        "path": str(p),
        "closed": len(closed),
        "remaining": [_row(fp) for fp in remaining],
        "new": [_row(fp) for fp in new],
        "verdict": ("all_closed" if not remaining and not new
                    else "still_vulnerable" if remaining
                    else "changed"),
    }
