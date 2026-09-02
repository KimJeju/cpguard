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

    class Meta:
        ordering = ["-created_at"]

    @property
    def findings(self) -> list[dict]:
        return json.loads(self.findings_json)

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
