"""대시보드 통합 테스트 — 업로드 → 안전해제 → 스캔 → 결과 렌더."""
import io
import os
import tempfile
import zipfile

import pytest

os.environ["CPGUARD_HOME"] = tempfile.mkdtemp(prefix="cpguard_test_")
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cpguard.web.settings")

import django  # noqa: E402

django.setup()
from django.conf import settings  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402

# 테스트 클라이언트는 host 헤더로 'testserver' 를 쓴다
settings.ALLOWED_HOSTS = ["testserver", "127.0.0.1", "localhost"]


@pytest.fixture(scope="module", autouse=True)
def _db():
    call_command("migrate", verbosity=0, interactive=False)


def _zip_bytes(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(name, data)
    buf.seek(0)
    buf.name = "project.zip"
    return buf


def test_index_loads():
    assert Client().get("/").status_code == 200


def test_upload_scan_and_detail():
    c = Client()
    z = _zip_bytes({
        "app/server.js": "app.get('/p', function(req,res){ const h=req.query.h; child_process.exec(h); });",
        "app/safe.js": "function s(req){ const h=shellQuote(req.query.h); child_process.exec(h); }",
    })
    r = c.post("/scan/", {"archive": z}, follow=True)
    assert r.status_code == 200
    body = r.content.decode("utf-8")
    assert "js.command-injection" in body      # 취약 파일은 탐지
    assert "CWE-78" in body
    assert body.count("js.command-injection") >= 1
    assert "req.query.h" in body                # 흐름 경로가 화면에 보인다


def test_zip_slip_upload_rejected():
    c = Client()
    z = _zip_bytes({"../evil.js": "pwned"})
    r = c.post("/scan/", {"archive": z}, follow=True)
    assert "안전하지 않은 아카이브" in r.content.decode("utf-8")


def test_non_zip_rejected():
    c = Client()
    f = io.BytesIO(b"not a zip")
    f.name = "x.txt"
    r = c.post("/scan/", {"archive": f}, follow=True)
    assert "zip 파일만" in r.content.decode("utf-8")


def test_cross_file_interprocedural_detection():
    """서로 다른 파일에 걸친 흐름도 탐지해야 한다."""
    c = Client()
    z = _zip_bytes({
        "lib/input.js": "function readInput(req){ return req.query.cmd; }\nmodule.exports = readInput;",
        "lib/run.js": "function runIt(v){ child_process.exec(v); }\nmodule.exports = runIt;",
        "app.js": "function handler(req,res){ const c = readInput(req); runIt(c); }",
    })
    r = c.post("/scan/", {"archive": z}, follow=True)
    body = r.content.decode("utf-8")
    assert "js.command-injection" in body


# ---------- 감사 작업대 ----------

def _seed_scan(c: Client) -> int:
    z = _zip_bytes({
        "app/server.js": "app.get('/p', function(req,res){ const h=req.query.h; child_process.exec(h); });",
        "app/conf.py": 'password = "hunter2secret"\n',
    })
    c.post("/scan/", {"archive": z}, follow=True)
    from cpguard.web.models import Scan
    return Scan.objects.first().pk


def test_workbench_renders_panes_and_data():
    c = Client()
    pk = _seed_scan(c)
    body = c.get(f"/scan/{pk}/").content.decode("utf-8")
    assert 'id="tree"' in body and 'id="code"' in body and 'id="detail"' in body
    assert 'id="data-findings"' in body and 'id="data-sources"' in body


def test_sources_are_stored_for_code_viewer():
    c = Client()
    pk = _seed_scan(c)
    from cpguard.web.models import Scan
    scan = Scan.objects.get(pk=pk)
    assert scan.sources, "코드 뷰어가 쓸 원본이 보관돼야 한다"
    assert any(p.endswith("server.js") for p in scan.sources)


def test_script_tag_in_source_cannot_break_out():
    """소스에 </script> 가 있어도 페이지 스크립트를 깨뜨리면 안 된다."""
    c = Client()
    z = _zip_bytes({
        "a.js": "// </script><img src=x onerror=alert(1)>\n"
                "app.get('/p', function(req,res){ child_process.exec(req.query.h); });",
    })
    c.post("/scan/", {"archive": z}, follow=True)
    from cpguard.web.models import Scan
    body = c.get(f"/scan/{Scan.objects.first().pk}/").content.decode("utf-8")
    assert "</script><img" not in body          # 원문 그대로 새어나오면 안 됨
    assert "\u003C" in body or "\u003c" in body  # json_script 가 이스케이프


def test_audit_state_persists():
    c = Client()
    pk = _seed_scan(c)
    r = c.post(f"/scan/{pk}/audit/", {"index": "0", "status": "confirmed"})
    assert r.json()["ok"] is True
    from cpguard.web.models import Scan
    assert Scan.objects.get(pk=pk).audit["0"] == "confirmed"


def test_audit_rejects_unknown_status():
    c = Client()
    pk = _seed_scan(c)
    r = c.post(f"/scan/{pk}/audit/", {"index": "0", "status": "hacked"})
    assert r.status_code == 400


def test_audit_requires_post():
    c = Client()
    pk = _seed_scan(c)
    assert c.get(f"/scan/{pk}/audit/").status_code == 405


def test_csv_export():
    c = Client()
    pk = _seed_scan(c)
    r = c.get(f"/scan/{pk}/export.csv")
    assert r.status_code == 200
    text = r.content.decode("utf-8-sig")
    assert "위험도" in text and "CWE" in text
    assert "js.command-injection" in text or "secret.hardcoded-password" in text


def test_scan_progress_status_and_page():
    """진행 상태 API 와 진행 화면 렌더 (백그라운드 잡 머신)."""
    import time as _t

    from cpguard.web import views
    c = Client()
    jid = "testjob_" + os.urandom(4).hex()
    views._job_set(jid, status="running", phase="parse", done=3, total=10,
                   findings=2, name="proj.zip", started=_t.time())

    d = c.get(f"/scan/progress/{jid}/status").json()
    assert d["status"] == "running" and d["total"] == 10 and d["phase"] == "parse"
    assert d["done"] == 3 and d["findings"] == 2

    page = c.get(f"/scan/progress/{jid}/")
    assert page.status_code == 200
    assert 'id="fill"' in page.content.decode("utf-8")   # 진행바 존재

    assert c.get("/scan/progress/does-not-exist/status").status_code == 404


def test_run_scan_job_creates_scan():
    """백그라운드 잡 함수가 압축해제→스캔→Scan 생성까지 하고 done/pk 를 남긴다."""
    from pathlib import Path

    from cpguard.web import views
    z = _zip_bytes({"a.js": "app.get('/p',function(req,res){child_process.exec(req.query.h);});"})
    workdir = Path(tempfile.mkdtemp(prefix="cpguard_job_"))
    (workdir / "upload.zip").write_bytes(z.getvalue())
    jid = "job_" + os.urandom(4).hex()
    views._job_set(jid, status="running", name="a.zip", started=0)
    views._run_scan_job(jid, workdir, "a.zip", False, "")
    job = views._job_get(jid)
    assert job["status"] == "done" and isinstance(job.get("pk"), int)
    assert job["findings"] >= 1
