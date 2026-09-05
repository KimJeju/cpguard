"""합본 진단 결과 보고서 — 다중 프로젝트를 한 건의 진단으로 묶는 산출물."""
import io
import os
import re
import tempfile
import zipfile

import pytest

os.environ.setdefault("CPGUARD_HOME", tempfile.mkdtemp(prefix="cpguard_con_"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cpguard.web.settings")

import django  # noqa: E402

django.setup()
from django.conf import settings  # noqa: E402
from django.core.files.uploadedfile import SimpleUploadedFile  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402

from cpguard.report import consolidated as C  # noqa: E402
from cpguard.web.models import Scan  # noqa: E402

settings.ALLOWED_HOSTS = ["testserver", "127.0.0.1", "localhost"]

# 스캐너가 탐지해야 할 취약 픽스처다 — 실행되지 않고 문자열로만 쓰인다.
VULN_JS = ("app.get('/x',(req,res)=>{eval(req.query.q)})\n"
           "app.get('/y',(req,res)=>{res.redirect(req.query.u)})\n")
VULN_PHP = '<?php $q=$_GET["q"]; mysqli_query($c,"select $q"); ?>'


@pytest.fixture(scope="module", autouse=True)
def _db():
    call_command("migrate", verbosity=0, interactive=False)


def _upload(c: Client, name: str, files: dict) -> Scan:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    c.post("/scan/", {"archive": SimpleUploadedFile(name, buf.getvalue()),
                      "standards": ["mois", "efs"]}, SERVER_NAME="127.0.0.1")
    return Scan.objects.order_by("-id").first()


@pytest.fixture(scope="module")
def two_projects():
    c = Client()
    a = _upload(c, "svc-alpha.zip", {"src/a.js": VULN_JS, "src/b.php": VULN_PHP})
    b = _upload(c, "svc-beta.zip", {"src/c.js": VULN_JS * 3})
    # 진단원 판정: 1건 오탐, 1건 제외 — 3.2 절과 최초/최종 차이를 만든다
    for idx, state, note in [(0, "false_positive", "출력 경로가 상수로 고정되어 성립하지 않음."),
                             (1, "deferred", "3rd-party 라이브러리 코드로 수정 대상 아님.")]:
        c.post(f"/scan/{a.pk}/audit/", {"index": idx, "status": state}, SERVER_NAME="127.0.0.1")
        c.post(f"/scan/{a.pk}/note/", {"index": idx, "note": note}, SERVER_NAME="127.0.0.1")
    return c, Scan.objects.get(pk=a.pk), Scan.objects.get(pk=b.pk)


def test_scan_records_scale_for_the_report(two_projects):
    """'파일 수 / 빌드 라인 / 개발언어' 는 보고서의 진단 규모 근거다 — 스캔 때 기록해야 한다."""
    _c, a, _b = two_projects
    assert a.file_count == 2
    assert a.code_lines > 0
    assert set(a.language_list) == {"javascript", "php"}


def test_audit_verdicts_split_initial_from_final(two_projects):
    """정적 분석 결과를 그대로 내면 발주처가 받지 않는다.

    진단원이 오탐·제외로 판정한 건은 최종 조치대상에서 빠지고, 그 사유가 3.2 절이 된다."""
    _c, a, b = two_projects
    d = C.build([a, b], ["mois", "efs"])
    assert d["projects"] == 2
    assert d["initial_total"]["total"] == len(a.findings) + len(b.findings)
    assert d["final_total"]["total"] == d["initial_total"]["total"] - 2
    reasons = {r["reason"] for r in d["review"]}
    assert reasons == {"오탐", "제외"}
    assert all(r["opinion"] for r in d["review"]), "진단원 의견이 비면 산출물이 안 된다"


def test_consolidated_pdf_has_the_submission_structure(two_projects):
    c, a, b = two_projects
    from pypdf import PdfReader
    r = c.get(f"/reports/consolidated?scan={a.pk}&scan={b.pk}&std=mois&std=efs&fmt=pdf",
              SERVER_NAME="127.0.0.1")
    assert r.status_code == 200 and r["Content-Type"] == "application/pdf"
    txt = "".join((p.extract_text() or "") for p in PdfReader(io.BytesIO(r.content)).pages)
    for section in ("1. 취약점 진단 개요", "1.3 점검 도구", "1.4 점검 수행 인원", "2. 진단 항목",
                    "3.1 최초 보안약점 진단 결과", "3.2 진단 결과 점검", "3.3 최종 점검 결과",
                    "4. 유형별 조치 권고", "5. 종합 의견"):
        assert section in txt, f"빠진 절: {section}"
    assert "svc-alpha" in txt and "svc-beta" in txt      # 프로젝트별 상세
    assert "진단원 의견" in txt
    assert "부록" not in txt                              # 제출본에서 뺀 절
    m = re.search(r"최초 (\d+)건에서 최종 (\d+)건", txt)
    assert m and int(m.group(1)) - int(m.group(2)) == 2


def test_consolidated_word_has_the_same_sections(two_projects):
    c, a, b = two_projects
    from docx import Document
    r = c.get(f"/reports/consolidated?scan={a.pk}&scan={b.pk}&std=mois&fmt=docx",
              SERVER_NAME="127.0.0.1")
    assert r.status_code == 200 and "wordprocessingml" in r["Content-Type"]
    d = Document(io.BytesIO(r.content))
    heads = [p.text for p in d.paragraphs if p.style.name.startswith("Heading")]
    for section in ("1. 취약점 진단 개요", "2. 진단 항목", "3. 진단 결과",
                    "3.2 진단 결과 점검", "4. 유형별 조치 권고", "5. 종합 의견"):
        assert section in heads, f"빠진 절: {section}"
    assert any(h.startswith("3.3.1 ") for h in heads)     # 프로젝트별 상세


def test_consolidated_needs_at_least_one_project():
    c = Client()
    assert c.get("/reports/consolidated?fmt=pdf", SERVER_NAME="127.0.0.1").status_code == 400


def test_report_is_only_built_from_the_reports_screen(two_projects):
    """합본은 여러 프로젝트를 묶는 산출물이라 스캔 하나를 보는 검토 화면에서 만들 수 없다."""
    c, a, _b = two_projects
    body = c.get(f"/scan/{a.pk}/", SERVER_NAME="127.0.0.1").content.decode("utf-8")
    assert f"/scan/{a.pk}/report.pdf" not in body
    assert f"/scan/{a.pk}/report.docx" not in body
    assert "/reports/" in body

    page = c.get("/reports/", SERVER_NAME="127.0.0.1").content.decode("utf-8")
    assert 'name="scan"' in page and 'name="std"' in page
    assert "/reports/consolidated" in page
