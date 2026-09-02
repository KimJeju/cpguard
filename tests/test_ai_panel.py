"""AI 분석 패널 검증 — 맥락 구성과 엔드포인트. 실제 LLM 호출 없이 가짜 프로바이더."""
import io
import os
import tempfile
import zipfile

import pytest

os.environ.setdefault("CPGUARD_HOME", tempfile.mkdtemp(prefix="cpguard_ai_"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cpguard.web.settings")

import django  # noqa: E402

django.setup()
from django.conf import settings  # noqa: E402
from django.core.management import call_command  # noqa: E402
from django.test import Client  # noqa: E402

settings.ALLOWED_HOSTS = ["testserver", "127.0.0.1", "localhost"]

from cpguard.triage import PRESETS, llm, providers  # noqa: E402
from cpguard.web.models import Scan  # noqa: E402

VULN = "app.get('/p', function(req,res){ const h = req.query.h; child_process.exec(h); });"


@pytest.fixture(scope="module", autouse=True)
def _db():
    call_command("migrate", verbosity=0, interactive=False)


class FakeProvider:
    name = "fake"

    def __init__(self):
        self.calls = []

    def complete_text(self, system, prompt):
        self.calls.append((system, prompt))
        return "취약합니다. a.js:1 에서 req.query.h 가 정제 없이 exec 로 갑니다."

    def complete_json(self, system, prompt):
        return {"results": []}


def _seed(c: Client, project="aiproj") -> Scan:
    Scan.objects.filter(project=project).delete()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("a.js", VULN)
    buf.seek(0)
    buf.name = f"{project}-main.zip"
    c.post("/scan/", {"archive": buf}, follow=True)
    return Scan.objects.filter(project=project).first()


# ---------- 맥락 구성 ----------

def test_context_block_has_flow_and_code():
    c = Client()
    scan = _seed(c)
    f = scan.findings[0]
    block = llm._context_block(f, scan.sources)
    assert f["rule_id"] in block and "데이터 흐름" in block
    assert "[source]" in block and "[sink]" in block
    assert "child_process.exec" in block            # 주변 코드가 붙는다
    assert "|" in block                              # 줄번호 표시


def test_presets_cover_investigation_workflow():
    for key in ("explain", "why", "trace", "exploit", "validate", "fix", "guidance"):
        assert key in PRESETS


def test_ask_uses_preset_or_custom_question(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(llm, "get_provider", lambda name=None, api_key=None, model=None: fake)
    c = Client()
    scan = _seed(c)
    f = scan.findings[0]

    llm.ask(f, scan.sources, preset="fix")
    assert PRESETS["fix"] in fake.calls[-1][1]
    llm.ask(f, scan.sources, question="이 정제가 우회 가능한가?")
    assert "우회 가능한가" in fake.calls[-1][1]
    assert fake.calls[-1][0].startswith("당신은")


# ---------- 엔드포인트 ----------

def test_ai_endpoint_returns_answer(monkeypatch):
    fake = FakeProvider()
    monkeypatch.setattr(llm, "get_provider", lambda name=None, api_key=None, model=None: fake)
    c = Client()
    scan = _seed(c)
    r = c.post(f"/scan/{scan.pk}/ai/", {"index": "0", "preset": "why"})
    d = r.json()
    assert d["ok"] is True and d["provider"] == "fake" and "취약" in d["answer"]


def test_ai_endpoint_without_key_gives_guidance(monkeypatch):
    for cls in providers.PROVIDERS.values():
        monkeypatch.delenv(cls.env_key, raising=False)
    c = Client()
    scan = _seed(c)
    d = c.post(f"/scan/{scan.pk}/ai/", {"index": "0", "preset": "explain"}).json()
    assert d["ok"] is False and d["unavailable"] is True
    assert "API_KEY" in d["error"]


def test_ai_endpoint_validates_input():
    c = Client()
    scan = _seed(c)
    assert c.post(f"/scan/{scan.pk}/ai/", {"index": "x"}).status_code == 400
    assert c.post(f"/scan/{scan.pk}/ai/", {"index": "999"}).status_code == 404
    assert c.post(f"/scan/{scan.pk}/ai/", {"index": "0", "preset": "nope"}).status_code == 400
    assert c.get(f"/scan/{scan.pk}/ai/").status_code == 405


def test_workbench_has_bottom_panel_and_table_view():
    c = Client()
    scan = _seed(c)
    body = c.get(f"/scan/{scan.pk}/").content.decode("utf-8")
    for marker in ('id="bottom"', 'data-tab="ai"', 'id="v-table"', 'id="g-left"', 'id="crumb"', 'data-preset="fix"'):
        assert marker in body
