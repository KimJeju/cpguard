"""스캔 이력 저장."""
from __future__ import annotations

import json

from django.db import models


class Scan(models.Model):
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    file_count = models.IntegerField(default=0)
    finding_count = models.IntegerField(default=0)
    findings_json = models.TextField(default="[]")
    sarif_json = models.TextField(default="{}")
    triage_note = models.CharField(max_length=500, blank=True, default="")
    integrity_note = models.CharField(max_length=500, blank=True, default="")
    # 탐지가 있는 파일의 원본 — 코드 뷰어가 흐름을 원문 위에 표시하려면 필요하다
    sources_json = models.TextField(default="{}")
    # 사람이 확정한 감사 결과 (finding 인덱스 -> 상태)
    audit_json = models.TextField(default="{}")
    # 프로젝트 = 같은 대상의 스캔 묶음. 스캔 간 신규/해결 비교와 추세의 단위.
    project = models.CharField(max_length=255, blank=True, default="", db_index=True)
    new_count = models.IntegerField(default=0)        # 이전 스캔 대비 신규
    resolved_count = models.IntegerField(default=0)   # 이전 스캔에 있었으나 사라짐

    def previous(self):
        """같은 프로젝트의 직전 스캔."""
        if not self.project:
            return None
        return (Scan.objects.filter(project=self.project, created_at__lt=self.created_at)
                .order_by("-created_at").first())

    def compare_with(self, prev) -> dict:
        """지문(fp) 기준으로 신규/해결/유지 집합을 낸다. 줄 번호가 밀려도 같은 이슈로 본다."""
        cur = {f.get("fp"): f for f in self.findings if f.get("fp")}
        old = {f.get("fp"): f for f in (prev.findings if prev else []) if f.get("fp")}
        return {
            "new": [cur[k] for k in cur.keys() - old.keys()],
            "resolved": [old[k] for k in old.keys() - cur.keys()],
            "persistent": [cur[k] for k in cur.keys() & old.keys()],
            "new_fps": set(cur.keys() - old.keys()),
        }

    class Meta:
        ordering = ["-created_at"]

    @property
    def findings(self) -> list[dict]:
        fs = json.loads(self.findings_json)
        for i, f in enumerate(fs):
            f.setdefault("id", i)   # 구버전/외부 생성 스캔에 id 가 없어도 안전
        return fs

    @property
    def sources(self) -> dict[str, str]:
        return json.loads(self.sources_json)

    @property
    def audit(self) -> dict[str, str]:
        return json.loads(self.audit_json)

    def set_audit(self, index: int, status: str) -> None:
        a = self.audit
        if status:
            a[str(index)] = status
        else:
            a.pop(str(index), None)
        self.audit_json = json.dumps(a)
        self.save(update_fields=["audit_json"])

    @property
    def rule_counts(self) -> list[tuple[str, int]]:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f["rule_id"]] = c.get(f["rule_id"], 0) + 1
        return sorted(c.items(), key=lambda x: -x[1])

    @property
    def file_counts(self) -> list[tuple[str, int]]:
        c: dict[str, int] = {}
        for f in self.findings:
            c[f["file"]] = c.get(f["file"], 0) + 1
        return sorted(c.items(), key=lambda x: -x[1])

    @property
    def verdict_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            v = f.get("verdict")
            if v:
                out[v] = out.get(v, 0) + 1
        return out

    @property
    def severity_counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.findings:
            out[f["severity"]] = out.get(f["severity"], 0) + 1
        return out


class FindingRow(models.Model):
    """탐지 1건의 인덱스된 행 — 서버측 필터·정렬·집계·페이지네이션용(대량 탐지 대응).

    findings_json(전체 blob)과 별개로, 5만 건 규모에서도 O(page) 질의가 되도록
    스캔 생성 시 함께 적재한다. 상세 흐름/코드는 여전히 findings_json 에서 본다.
    """
    scan = models.ForeignKey(Scan, related_name="rows", on_delete=models.CASCADE)
    idx = models.IntegerField()                       # 스캔 내 finding id
    severity = models.CharField(max_length=12, db_index=True)
    rule_id = models.CharField(max_length=100, db_index=True)
    cwe = models.CharField(max_length=24, blank=True, default="")
    owasp = models.CharField(max_length=100, blank=True, default="")
    file = models.CharField(max_length=600, db_index=True)
    line = models.IntegerField(default=0)
    fp = models.CharField(max_length=40, blank=True, default="", db_index=True)
    category = models.CharField(max_length=20, blank=True, default="")
    verdict = models.CharField(max_length=20, blank=True, default="")
    message = models.TextField(blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["scan", "severity"]),
            models.Index(fields=["scan", "rule_id"]),
        ]
