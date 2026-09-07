"""프로젝트 홈이 '이번 진단이 어떤 조건으로 돌았는지' 를 실제로 그리는지 본다.

규칙 오버레이와 SCA 수행 여부는 결과를 바꾼다. 산출물에만 있고 화면에 없으면 진단원이
두 진단의 차이가 왜 생겼는지 못 찾는다.
"""
import json
import os
import tempfile

import pytest

os.environ["CPGUARD_HOME"] = tempfile.mkdtemp(prefix="cpguard_home_")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cpguard.web.settings")

import django  # noqa: E402

django.setup()
from django.conf import settings  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402

settings.ALLOWED_HOSTS = ["testserver", "127.0.0.1", "localhost"]


@pytest.fixture(scope="module", autouse=True)
def _db():
    call_command("migrate", run_syncdb=True, verbosity=0)


def _make(project: str, config: dict):
    from cpguard.web.models import Scan
    return Scan.objects.create(
        name=f"{project}.zip", project=project, finding_count=0,
        findings_json="[]", scan_config_json=json.dumps(config, ensure_ascii=False))


def _html(project: str) -> str:
    r = Client().get(f"/project/{project}/")
    assert r.status_code == 200
    return r.content.decode("utf-8")


def test_shows_applied_overlay_and_sca_summary():
    _make("withsca", {"tuned_specs": ["java_sqli", "acme_internal"],
                      "sca": True, "sca_note": "SCA: 컴포넌트 12건 중 3건의 알려진 취약점을 확인했다."})
    html = _html("withsca")
    assert "규칙 조정 2건" in html and "SCA 수행" in html
    assert "java_sqli" in html and "acme_internal" in html
    assert "컴포넌트 12건 중 3건" in html


def test_says_so_when_nothing_was_tuned_and_sca_skipped():
    _make("plain", {})
    html = _html("plain")
    assert "규칙 조정 0건" in html and "SCA 미수행" in html
    assert "~/.cpguard/specs/" in html, "조정하는 방법을 알려줘야 설정 기능이 존재한다"
    assert "수행하지 않았습니다" in html
