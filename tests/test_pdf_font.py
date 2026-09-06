"""한글 폰트 처리 — 동봉 폰트로 항상 나오고, 그마저 없으면 만들지 않고 멈춘다.

리눅스 서버에는 한글 폰트가 기본 설치되지 않는다. 폴백으로 그냥 만들면 본문이 전부
■ 로 찍힌 PDF 가 발주처로 나가는데, 파일은 정상으로 보여서 아무도 못 잡는다.
"""
import io

import pytest

from cpguard.report import pdf


@pytest.fixture
def no_system_font(monkeypatch):
    """시스템 한글 폰트가 하나도 없는 리눅스 서버 상황."""
    monkeypatch.setattr(pdf, "_FONT", "Helvetica")
    monkeypatch.setattr(pdf, "_FONT_CANDIDATES", [])
    monkeypatch.setattr(pdf, "_FONT_DIRS", [])
    monkeypatch.delenv("CPGUARD_PDF_FONT", raising=False)


def test_bundled_font_renders_korean(no_system_font):
    from pypdf import PdfReader
    from reportlab.pdfgen.canvas import Canvas

    pdf._register_font("ko")
    assert pdf._FONT == pdf._KO          # 동봉 폰트로 등록됐다

    buf = io.BytesIO()
    c = Canvas(buf)
    c.setFont(pdf._FONT, 12)
    c.drawString(50, 700, "취약점 진단 결과 보고서")
    c.save()

    txt = PdfReader(io.BytesIO(buf.getvalue())).pages[0].extract_text()
    assert "취약점 진단 결과 보고서" in txt and "■" not in txt


def test_korean_report_refuses_to_build_without_any_font(no_system_font, monkeypatch):
    monkeypatch.setattr(pdf, "_BUNDLED", ("/nonexistent/ko.ttf", None))
    with pytest.raises(pdf.KoreanFontMissing):
        pdf._register_font("ko")


def test_english_report_still_builds_without_a_korean_font(no_system_font, monkeypatch):
    monkeypatch.setattr(pdf, "_BUNDLED", ("/nonexistent/ko.ttf", None))
    pdf._register_font("en")             # 영문 산출물은 Helvetica 로 충분
