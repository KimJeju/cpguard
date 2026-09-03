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
    # 다운로드 링크는 download 속성이 있어야 한다: 네이티브 WebView2 가 PDF 를 창 안에서
    # 열어(뷰어 탈취) 먹통 되는 것을 막고 실제 다운로드로 보낸다.
    assert 'download href="/scan/%d/report.pdf"' % pk in body
    assert 'download href="/scan/%d/export.xlsx"' % pk in body


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


def test_audit_note_saves_as_plaintext():
    c = Client()
    pk = _seed_scan(c)
    from cpguard.web.models import Scan
    payload = "오탐 근거: 테스트 코드 <script>alert(1)</script>"
    r = c.post(f"/scan/{pk}/note/", {"index": "0", "note": payload})
    assert r.json()["ok"] is True
    # 평문 그대로 저장(렌더는 프런트에서 escape) — 저장 단계에서 변형하지 않는다
    assert Scan.objects.get(pk=pk).audit_notes["0"] == payload
    # 상세/작업대 응답이 note 를 실어 준다
    d = c.get(f"/scan/{pk}/api/finding/0").json()
    assert d["finding"]["audit_note"] == payload
    # 빈 값으로 저장하면 삭제
    c.post(f"/scan/{pk}/note/", {"index": "0", "note": "  "})
    assert "0" not in Scan.objects.get(pk=pk).audit_notes


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


def test_downloads_are_no_store():
    """다운로드 응답은 캐시 금지여야 한다.

    SQLite 는 삭제된 pk(rowid)를 재사용한다. 네이티브 WebView2 가 /scan/<pk>/export.*
    GET 을 캐시하면, 같은 pk 를 다른 프로젝트 스캔이 재획득했을 때 이전 프로젝트의
    파일이 내려간다(현장 재현 버그). never_cache 로 이를 막는다.
    """
    c = Client()
    pk = _seed_scan(c)
    for url in (f"/scan/{pk}/export.xlsx", f"/scan/{pk}/export.csv",
                f"/scan/{pk}/sarif/", f"/scan/{pk}/report.pdf", f"/scan/{pk}/guide.pdf"):
        r = c.get(url)
        assert r.status_code == 200, url
        assert "no-store" in r.headers.get("Cache-Control", ""), url


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
    body = page.content.decode("utf-8")
    assert 'id="steps"' in body and 'id="log"' in body   # 단계 체크리스트·로그 존재
    assert 'id="goto"' in body                            # 프로젝트로 이동 버튼

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


def test_settings_save_mask_and_clear():
    """설정 저장 → 마스킹 표시 → 삭제. 환경 오염은 끝에 정리."""
    import os as _os

    from cpguard.web import config as appcfg
    c = Client()
    try:
        r = c.post("/settings/", {"ANTHROPIC_API_KEY": "sk-ant-DUMMY1234567890abcd"})
        assert r.status_code in (302, 200)
        assert appcfg.load().get("ANTHROPIC_API_KEY") == "sk-ant-DUMMY1234567890abcd"
        body = c.get("/settings/").content.decode("utf-8")
        assert "설정됨" in body and "•" in body          # 마스킹 표시
        assert "sk-ant-DUMMY1234567890abcd" not in body  # 원본 노출 안 함
        # 삭제
        c.post("/settings/", {"clear_ANTHROPIC_API_KEY": "1"})
        assert "ANTHROPIC_API_KEY" not in appcfg.load()
    finally:
        appcfg.save({})
        _os.environ.pop("ANTHROPIC_API_KEY", None)


def test_secrets_only_skips_dataflow():
    """secrets_only 스캔은 데이터 흐름 축을 건너뛰고 패턴만 탐지한다."""
    from cpguard.scanner import scan_path
    d = tempfile.mkdtemp(prefix="cpguard_so_")
    with open(os.path.join(d, "a.py"), "w", encoding="utf-8") as f:
        f.write('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
                'q = "SELECT * FROM t WHERE x=" + user\n')
    findings, report = scan_path(d, secrets_only=True)
    assert report.scanned == 0                       # 소스 파싱 축 생략
    cats = {getattr(f, "category", "flow") for f in findings}
    assert "flow" not in cats                         # 데이터 흐름 finding 없음
    assert any(f.category in ("secret", "pii", "config", "infra", "hygiene") for f in findings)


def test_dashboard_shows_stats():
    c = Client()
    body = c.get("/").content.decode("utf-8")
    assert "위험도 분포" in body and "상위 탐지 규칙" in body   # 대시보드 위젯
    assert "총 탐지" in body                                    # 상태 타일


def test_compare_and_reports_pages():
    c = Client()
    assert c.get("/compare/").status_code == 200
    assert c.get("/reports/").status_code == 200


def test_settings_saves_model_override():
    import os as _os

    from cpguard.web import config as appcfg
    c = Client()
    try:
        c.post("/settings/", {"model_gemini": "gemini-3.6-pro"})
        assert appcfg.model_for("gemini") == "gemini-3.6-pro"
        # 비우면 기본으로 복귀
        c.post("/settings/", {"model_gemini": ""})
        assert appcfg.model_for("gemini") is None
    finally:
        appcfg.save({})
        _os.environ.pop("GEMINI_API_KEY", None)


def test_pdf_report_and_guide_download():
    """합본 보고서·조치가이드 PDF 다운로드 (유효한 PDF)."""
    c = Client()
    pk = _seed_scan(c)
    for url in (f"/scan/{pk}/report.pdf", f"/scan/{pk}/guide.pdf"):
        r = c.get(url)
        assert r.status_code == 200
        assert r["Content-Type"] == "application/pdf"
        assert r.content[:5] == b"%PDF-"       # PDF 매직
        assert len(r.content) > 1500


def test_upload_accepts_model_override():
    from cpguard.web import views
    from pathlib import Path
    z = _zip_bytes({"a.js": "app.get('/p',function(req,res){child_process.exec(req.query.h);});"})
    workdir = Path(tempfile.mkdtemp(prefix="cpguard_m_"))
    (workdir / "upload.zip").write_bytes(z.getvalue())
    jid = "jm_" + os.urandom(4).hex()
    views._job_set(jid, status="running", name="a.zip", started=0)
    # model 인자를 받아도 정상 완료 (트리아지 off 라 실제 호출은 없음)
    views._run_scan_job(jid, workdir, "a.zip", False, "", False, "claude-haiku-4-5")
    assert views._job_get(jid)["status"] == "done"


def test_finding_rows_and_scale_apis():
    """FindingRow 적재 + 집계/페이지네이션 API (대량 탐지 서버측 질의)."""
    c = Client()
    pk = _seed_scan(c)
    from cpguard.web.models import FindingRow
    assert FindingRow.objects.filter(scan_id=pk).count() > 0

    s = c.get(f"/scan/{pk}/api/summary").json()
    assert s["total"] > 0 and s["severity"] and s["top_rules"]
    # 프로젝트 홈 차트가 쓰는 확장 집계 필드
    assert "by_category" in s and "top_cwe" in s and "by_verdict" in s

    d = c.get(f"/scan/{pk}/api/findings?size=1&page=1").json()
    assert d["size"] == 1 and len(d["rows"]) <= 1 and d["total"] >= 1
    assert {"severity", "rule_id", "file", "line"} <= set(d["rows"][0].keys())

    hi = c.get(f"/scan/{pk}/api/findings?severity=high").json()
    assert all(r["severity"] == "high" for r in hi["rows"])
