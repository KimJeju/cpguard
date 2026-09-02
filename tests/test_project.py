"""프로젝트·스캔 비교 검증 — 지문으로 스캔 간 같은 이슈를 잇고 신규/해결을 낸다."""
import io
import os
import tempfile
import zipfile

import pytest

os.environ.setdefault("CPGUARD_HOME", tempfile.mkdtemp(prefix="cpguard_proj_"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cpguard.web.settings")

import django  # noqa: E402

django.setup()
from django.conf import settings  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402

settings.ALLOWED_HOSTS = ["testserver", "127.0.0.1", "localhost"]

from cpguard.ir import Loc  # noqa: E402
from cpguard.report.finding import Finding, Step  # noqa: E402
from cpguard.web import views  # noqa: E402
from cpguard.web.models import Scan  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _db():
    call_command("migrate", verbosity=0, interactive=False)


def _finding(rule: str, file: str, line: int, code: str) -> Finding:
    loc = Loc(file=file, start_line=line, start_col=0, end_line=line, end_col=0,
              start_byte=0, end_byte=0)
    return Finding(rule_id=rule, message="m", severity="high", cwe="CWE-1",
                   steps=[Step("sink", loc, code)])


def _zip(files: dict[str, str], name: str) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in files.items():
            z.writestr(n, d)
    buf.seek(0)
    buf.name = name
    return buf


# ---------- 지문 ----------

def test_fingerprint_ignores_line_number_and_whitespace():
    a = views._fingerprint(_finding("js.sqli", "a.js", 10, "db.query(q)"), "a.js")
    b = views._fingerprint(_finding("js.sqli", "a.js", 42, "db.query( q )"), "a.js")
    assert a == b


def test_fingerprint_differs_by_rule_and_file():
    base = _finding("js.sqli", "a.js", 1, "db.query(q)")
    assert views._fingerprint(base, "a.js") != views._fingerprint(
        _finding("js.xss", "a.js", 1, "db.query(q)"), "a.js")
    assert views._fingerprint(base, "a.js") != views._fingerprint(base, "b.js")


@pytest.mark.parametrize("name,expected", [
    ("shop-main.zip", "shop"), ("shop-v2.3.zip", "shop"), ("shop_20260902.zip", "shop"),
    ("DVWA-master.zip", "DVWA"), ("plain.zip", "plain"),
])
def test_project_name_normalization(name, expected):
    assert views._project_of(name) == expected


# ---------- 스캔 비교 ----------

VULN = "app.get('/p', function(req,res){ child_process.exec(req.query.h); });"
SAFE = "app.get('/p', function(req,res){ res.send('ok'); });"
XSS = "app.get('/x', function(req,res){ res.send(req.query.m); });"


def test_second_scan_reports_new_and_resolved():
    c = Client()
    Scan.objects.filter(project="cmpproj").delete()
    c.post("/scan/", {"archive": _zip({"a.js": VULN}, "cmpproj-v1.zip")}, follow=True)
    # v2: 기존 취약점 해결, 새 취약점 등장 (다른 파일)
    c.post("/scan/", {"archive": _zip({"a.js": SAFE, "b.js": XSS}, "cmpproj-v2.zip")}, follow=True)

    scans = list(Scan.objects.filter(project="cmpproj").order_by("created_at"))
    assert len(scans) == 2
    first, second = scans
    assert first.previous() is None
    assert second.previous().pk == first.pk
    assert second.resolved_count >= 1        # a.js 의 명령 주입이 사라짐
    assert second.new_count >= 1             # b.js 의 XSS 가 새로 생김


def test_same_code_shifted_lines_is_not_new():
    """위에 줄이 추가돼 라인이 밀려도 같은 이슈로 봐야 한다."""
    c = Client()
    Scan.objects.filter(project="shiftproj").delete()
    c.post("/scan/", {"archive": _zip({"a.js": VULN}, "shiftproj-v1.zip")}, follow=True)
    c.post("/scan/", {"archive": _zip({"a.js": "// header\n// more\n" + VULN}, "shiftproj-v2.zip")},
           follow=True)
    second = Scan.objects.filter(project="shiftproj").order_by("-created_at").first()
    assert second.new_count == 0 and second.resolved_count == 0


# ---------- 프로젝트 홈 ----------

def test_project_home_renders_priority_and_trend():
    c = Client()
    Scan.objects.filter(project="homeproj").delete()
    c.post("/scan/", {"archive": _zip({"a.js": VULN}, "homeproj-v1.zip")}, follow=True)
    c.post("/scan/", {"archive": _zip({"a.js": VULN, "b.js": XSS}, "homeproj-v2.zip")}, follow=True)

    r = c.get("/project/homeproj/")
    assert r.status_code == 200
    body = r.content.decode("utf-8")
    assert "우선 조사 대상" in body and "추세" in body
    assert "NEW" in body                       # b.js 의 XSS 가 신규로 표시
    assert "신규 +1" in body


def test_unknown_project_redirects_home():
    assert Client().get("/project/nope-nothing/").status_code == 302


def test_workbench_marks_new_findings():
    c = Client()
    Scan.objects.filter(project="wbproj").delete()
    c.post("/scan/", {"archive": _zip({"a.js": VULN}, "wbproj-v1.zip")}, follow=True)
    c.post("/scan/", {"archive": _zip({"a.js": VULN, "b.js": XSS}, "wbproj-v2.zip")}, follow=True)
    latest = Scan.objects.filter(project="wbproj").order_by("-created_at").first()
    body = c.get(f"/scan/{latest.pk}/").content.decode("utf-8")
    assert '"is_new": true' in body and "wbproj 홈" in body
