"""Scan 에 위험도 카운트 컬럼 5개 추가 + 기존 스캔 백필.

포트폴리오(수백 프로젝트) 목록이 findings_json 을 역직렬화하지 않고
순수 DB 조회로 위험도를 집계하도록 비정규화한다.
"""
from __future__ import annotations

import json

from django.db import migrations, models


def backfill(apps, schema_editor):
    Scan = apps.get_model("web", "Scan")
    for scan in Scan.objects.all().iterator():
        try:
            findings = json.loads(scan.findings_json or "[]")
        except (ValueError, TypeError):
            findings = []
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity")
            if sev in c:
                c[sev] += 1
        scan.sev_critical = c["critical"]
        scan.sev_high = c["high"]
        scan.sev_medium = c["medium"]
        scan.sev_low = c["low"]
        scan.sev_info = c["info"]
        scan.save(update_fields=["sev_critical", "sev_high", "sev_medium", "sev_low", "sev_info"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [("web", "0006_scan_audit_notes_json")]

    operations = [
        migrations.AddField("scan", "sev_critical", models.IntegerField(default=0)),
        migrations.AddField("scan", "sev_high", models.IntegerField(default=0)),
        migrations.AddField("scan", "sev_medium", models.IntegerField(default=0)),
        migrations.AddField("scan", "sev_low", models.IntegerField(default=0)),
        migrations.AddField("scan", "sev_info", models.IntegerField(default=0)),
        migrations.RunPython(backfill, noop),
    ]
