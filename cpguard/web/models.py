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

    class Meta:
        ordering = ["-created_at"]

    @property
    def findings(self) -> list[dict]:
        return json.loads(self.findings_json)

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
