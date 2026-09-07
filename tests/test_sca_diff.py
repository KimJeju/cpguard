"""SCA 를 껐다 켰다 하면 신규/해결 비교가 거짓말을 하는지 본다.

SCA 를 끈 채 재진단하면 오픈소스 취약점이 전부 '해결됨' 으로 잡힌다. 조치하지 않은
것을 조치했다고 쓰는 산출물이 되므로, 두 스캔이 함께 본 축만 비교해야 한다.
"""
import json
import os
import tempfile

import pytest

os.environ["CPGUARD_HOME"] = tempfile.mkdtemp(prefix="cpguard_scadiff_")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cpguard.web.settings")

import django  # noqa: E402

django.setup()
from django.core.management import call_command  # noqa: E402

from cpguard.report.finding import fingerprint  # noqa: E402


def _f(idx, rule_id, file, code, category):
    return {"id": idx, "rule_id": rule_id, "file": file, "line": 1, "category": category,
            "severity": "high", "fp": fingerprint(rule_id, file, code),
            "steps": [{"kind": "sink", "file": file, "line": 1, "code": code}]}


CODE_FINDING = _f(0, "java.sqli", "Dao.java", "stmt.execute(q)", "flow")
DEP_FINDING = _f(1, "sca.vulnerable-dependency", "package-lock.json",
                 "npm:lodash@4.17.15  CVE-2020-8203", "dependency")


@pytest.fixture(scope="module")
def db():
    call_command("migrate", run_syncdb=True, verbosity=0)


def _scan(findings, sca: bool):
    from cpguard.web.models import Scan
    return Scan.objects.create(
        name="app.zip", project="app", finding_count=len(findings),
        findings_json=json.dumps(findings),
        scan_config_json=json.dumps({"sca": sca}))


def test_turning_sca_off_does_not_report_deps_as_resolved(db):
    prev = _scan([CODE_FINDING, DEP_FINDING], sca=True)
    cur = _scan([CODE_FINDING], sca=False)
    diff = cur.compare_with(prev)
    assert diff["resolved"] == [], "SCA 를 껐을 뿐인데 해결된 것으로 세면 안 된다"
    assert len(diff["persistent"]) == 1


def test_turning_sca_on_does_not_report_deps_as_new(db):
    prev = _scan([CODE_FINDING], sca=False)
    cur = _scan([CODE_FINDING, DEP_FINDING], sca=True)
    assert cur.compare_with(prev)["new"] == []


def test_same_coverage_still_compares_dependencies(db):
    prev = _scan([CODE_FINDING, DEP_FINDING], sca=True)
    cur = _scan([CODE_FINDING], sca=True)
    diff = cur.compare_with(prev)
    assert [f["rule_id"] for f in diff["resolved"]] == ["sca.vulnerable-dependency"]
