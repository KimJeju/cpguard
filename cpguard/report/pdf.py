"""PDF 산출 — 합본 진단 결과 보고서 · 유형별 조치 가이드.

reportlab(순수 파이썬, 번들 가능) + 시스템 맑은고딕(Windows). 폰트가 없으면
Helvetica 로 폴백(한글이 깨지므로 Windows 대상에선 malgun.ttf 를 쓴다).
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak,
                                PageTemplate, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)
from reportlab.platypus.tableofcontents import TableOfContents

from ..i18n import (DEFAULT_REM_EN, REMEDIATION_EN, SEV_EN, STEP_LABEL,
                    STEP_LABEL_EN, tr)

# ---- 폰트 등록 (한글) ----
_FONT = "Helvetica"
_FONT_B = "Helvetica-Bold"


def _register_font() -> None:
    global _FONT, _FONT_B
    if _FONT == "Malgun":
        return
    for reg, bold, name, bname in (
        ("C:/Windows/Fonts/malgun.ttf", "C:/Windows/Fonts/malgunbd.ttf", "Malgun", "MalgunB"),
        ("C:/Windows/Fonts/gulim.ttc", None, "Malgun", "MalgunB"),
    ):
        try:
            if Path(reg).exists():
                pdfmetrics.registerFont(TTFont("Malgun", reg))
                pdfmetrics.registerFont(TTFont("MalgunB", bold if bold and Path(bold).exists() else reg))
                _FONT, _FONT_B = "Malgun", "MalgunB"
                return
        except Exception:
            continue


SEV_KR = {"critical": "매우위험", "high": "위험", "medium": "보통", "low": "낮음", "info": "정보"}
SEV_COLOR = {"critical": colors.HexColor("#c0392b"), "high": colors.HexColor("#e67e22"),
             "medium": colors.HexColor("#b7950b"), "low": colors.HexColor("#2e7d32"),
             "info": colors.HexColor("#7f8c8d")}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

# 유형별 조치 권고 (rule_id 접미사 기준). (제목, 설명, 조치 권고, 안전 예시)
REMEDIATION = {
    "sqli": ("SQL 주입 (SQL Injection)",
             "사용자 입력이 검증 없이 SQL 질의에 문자열로 결합되어, 공격자가 쿼리 구조를 변경할 수 있습니다.",
             "문자열 결합 대신 파라미터 바인딩(Prepared Statement / 파라미터화 쿼리)을 사용합니다. ORM 사용 시 원시 쿼리 결합을 피합니다.",
             "db.query('SELECT * FROM users WHERE id = ?', [userId])"),
    "command-injection": ("명령어 삽입 (OS Command Injection)",
             "사용자 입력이 셸 명령 실행 함수로 전달되어 임의 명령이 실행될 수 있습니다.",
             "셸을 거치는 exec 대신 execFile/spawn 등에 명령과 인자를 분리해 전달하고, 입력값은 허용목록으로 검증합니다.",
             "child_process.execFile('convert', [inputPath, outputPath])"),
    "xss": ("크로스사이트 스크립팅 (XSS)",
             "사용자 입력이 이스케이프 없이 HTML 응답에 출력되어 스크립트가 실행될 수 있습니다.",
             "출력 시 컨텍스트에 맞는 이스케이프(HTML/속성/JS)를 적용하고, 템플릿 엔진의 자동 이스케이프를 사용합니다. innerHTML 대신 textContent 를 씁니다.",
             "el.textContent = userInput  // innerHTML 금지"),
    "path-traversal": ("경로 조작 (Path Traversal)",
             "사용자 입력이 파일 경로에 사용되어 상위 디렉터리(../) 접근이 가능할 수 있습니다.",
             "기준 디렉터리로 정규화(resolve) 후 접두 검사를 하고, 파일명은 허용목록/화이트리스트로 제한합니다.",
             "p = path.resolve(base, name); if(!p.startsWith(base)) throw"),
    "ssrf": ("서버측 요청 위조 (SSRF)",
             "사용자가 지정한 URL 로 서버가 요청을 보내 내부망 자원에 접근당할 수 있습니다.",
             "대상 호스트를 허용목록으로 제한하고, 사설 IP/메타데이터 주소(169.254.169.254 등)를 차단합니다.",
             "if(!ALLOWED_HOSTS.has(new URL(url).host)) reject()"),
    "code-injection": ("코드 삽입 (Code Injection)",
             "사용자 입력이 eval 등 동적 코드 실행에 전달되어 임의 코드가 실행될 수 있습니다.",
             "eval/new Function/동적 실행을 제거합니다. 데이터 파싱은 JSON.parse 등 안전한 대안을 사용합니다.",
             "const data = JSON.parse(input)  // eval 금지"),
    "file-inclusion": ("파일 삽입 (File Inclusion)",
             "사용자 입력이 include/require 경로에 사용되어 임의 파일이 포함될 수 있습니다.",
             "동적 포함 경로를 허용목록으로 제한하고 사용자 입력을 직접 경로로 쓰지 않습니다.",
             "$allowed = ['home','about']; include $allowed[$page] . '.php';"),
    "open-redirect": ("오픈 리다이렉트 (Open Redirect)",
             "사용자 입력이 리다이렉트 대상으로 사용되어 피싱에 악용될 수 있습니다.",
             "리다이렉트 대상을 내부 상대경로 또는 허용목록으로 제한합니다.",
             "if(!target.startsWith('/')) target = '/'"),
    "secret": ("하드코딩된 비밀정보 (Hardcoded Secret)",
             "비밀번호·API 키·토큰이 소스에 하드코딩되어 유출 위험이 있습니다.",
             "비밀정보는 환경변수·비밀관리(Secret Manager)로 분리하고, 노출된 키는 즉시 폐기·교체합니다.",
             "apiKey = process.env.API_KEY"),
    "pii": ("개인정보 노출 (PII)",
             "주민번호·카드번호·연락처 등 개인정보가 소스/설정에 포함되어 있습니다.",
             "실데이터를 소스에서 제거하고, 저장 시 암호화·마스킹을 적용합니다.",
             "// 실데이터 대신 환경/보안저장소 참조"),
    "tls": ("TLS 검증 비활성화",
            "인증서 검증을 끄면 중간자 공격에 노출됩니다.",
            "인증서 검증을 활성화하고, 필요한 내부 CA 는 신뢰저장소에 등록합니다.",
            "verify=True  // rejectUnauthorized: true"),
    "crypto": ("취약한 암호/해시",
               "MD5/SHA-1/DES/ECB 등 취약한 알고리즘 사용이 발견되었습니다.",
               "SHA-256 이상, AES-GCM 등 안전한 알고리즘으로 교체하고 비밀번호는 bcrypt/argon2 로 해시합니다.",
               "hashlib.sha256(x)  // bcrypt for passwords"),
}
_DEFAULT_REM = ("보안약점", "탐지된 유형에 대한 조치가 필요합니다.",
                "해당 CWE 의 권고사항에 따라 입력 검증·출력 인코딩·최소권한 원칙을 적용합니다.", "")


def _rule_key(rule_id: str) -> str:
    """rule_id -> 조치 맵 키. 언어 접두(js./php./py.) 제거 후 접미 매칭."""
    tail = rule_id.split(".")[-1]
    for k in REMEDIATION:
        if k in tail or k in rule_id:
            return k
    if rule_id.startswith("secret") or "secret" in rule_id:
        return "secret"
    if rule_id.startswith("pii"):
        return "pii"
    if "sql" in rule_id:
        return "sqli"
    return ""


def _styles():
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["Normal"], fontName=_FONT, fontSize=9.5, leading=15)
    # h1 = 대단원(TOC L0), h2sec = 중단원(TOC L1). afterFlowable 가 이 스타일명으로 목차를 만든다.
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName=_FONT_B, fontSize=15, spaceBefore=14, spaceAfter=8,
                        textColor=colors.HexColor("#1a2740"))
    h2sec = ParagraphStyle("h2sec", parent=ss["Heading2"], fontName=_FONT_B, fontSize=11.5, spaceBefore=10, spaceAfter=4,
                          textColor=colors.HexColor("#2a3a55"))
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName=_FONT_B, fontSize=12, spaceBefore=10, spaceAfter=5)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, textColor=colors.HexColor("#555"))
    lbl = ParagraphStyle("lbl", parent=body, fontName=_FONT_B, fontSize=9, textColor=colors.HexColor("#333"))
    cardt = ParagraphStyle("cardt", parent=body, fontName=_FONT_B, fontSize=10.5, textColor=colors.white, leading=14)
    code = ParagraphStyle("code", parent=body, fontName="Courier", fontSize=8, textColor=colors.HexColor("#0a3"),
                          backColor=colors.HexColor("#f4f4f4"), borderPadding=4, leading=11)
    flow = ParagraphStyle("flow", parent=body, fontName="Courier", fontSize=8, leading=12,
                          textColor=colors.HexColor("#333"))
    return {"body": body, "h1": h1, "h2": h2, "h2sec": h2sec, "small": small,
            "lbl": lbl, "cardt": cardt, "code": code, "flow": flow}


def _sev_chart(counts, sevmap):
    """위험도 분포 가로 막대 — 회색·검정 톤, 옅은 회색 테두리.

    주의: reportlab HexColor 는 3자리(#eee)를 6자리로 펼치지 않는다(0x000EEE=파랑).
    반드시 6자리로 쓴다."""
    order = SEV_ORDER
    mx = max([counts.get(s, 0) for s in order] + [1])
    row_h, bar_w, pad = 20, 300, 8
    W, H = 460, row_h * len(order) + pad * 2
    d = Drawing(W, H)
    # 겉 테두리(옅은 회색, 얇게)
    d.add(Rect(0.5, 0.5, W - 1, H - 1, fillColor=colors.white,
               strokeColor=colors.HexColor("#d9d9d9"), strokeWidth=0.6))
    y = H - pad - row_h + 4
    for s in order:
        n = counts.get(s, 0)
        w = (n / mx) * bar_w if n else 0
        d.add(String(pad + 2, y + 3, sevmap[s], fontName=_FONT, fontSize=9, fillColor=colors.HexColor("#222222")))
        d.add(Rect(78, y, bar_w, 12, fillColor=colors.HexColor("#eeeeee"), strokeColor=None))
        if w:
            d.add(Rect(78, y, w, 12, fillColor=colors.HexColor("#3a3a3a"), strokeColor=None))
        d.add(String(78 + bar_w + 8, y + 3, str(n), fontName=_FONT_B, fontSize=9, fillColor=colors.HexColor("#222222")))
        y -= row_h
    return d


def _kv_table(rows, T, col0=50 * mm, col1=124 * mm):
    """항목/값 2열 표(개요·범위·방법)."""
    data = [[T(k), v] for k, v in rows]
    t = Table(data, colWidths=[col0, col1])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("FONTNAME", (0, 0), (0, -1), _FONT_B),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f5f8")),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#334")),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dae2")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _cover(story, st, title, subtitle, meta_rows):
    center = ParagraphStyle("cvc", parent=st["body"], alignment=TA_CENTER)
    story.append(Spacer(1, 45 * mm))
    story.append(Paragraph("SOURCE CODE SECURITY ASSESSMENT", ParagraphStyle("c0", parent=center, fontName=_FONT, fontSize=11, textColor=colors.HexColor("#888"))))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(title, ParagraphStyle("c1", parent=center, fontName=_FONT_B, fontSize=22, leading=30)))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(subtitle, ParagraphStyle("c2", parent=center, fontName=_FONT, fontSize=13, textColor=colors.HexColor("#444"))))
    story.append(Spacer(1, 30 * mm))
    t = Table([[k, v] for k, v in meta_rows], colWidths=[50 * mm, 124 * mm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#ddd")),
    ]))
    story.append(t)
    story.append(PageBreak())


def _severity_table(story, st, counts, sevmap, T):
    total = sum(counts.get(s, 0) for s in SEV_ORDER)
    head = [T("위험도")] + [sevmap[s] for s in SEV_ORDER] + [T("합계")]
    row = [T("개수")] + [str(counts.get(s, 0)) for s in SEV_ORDER] + [str(total)]
    t = Table([head, row], colWidths=[30 * mm] + [24 * mm] * 5 + [24 * mm])
    style = [("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 9),
             ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#ccc")),
             ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
             ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
    for i, s in enumerate(SEV_ORDER, 1):
        style.append(("TEXTCOLOR", (i, 1), (i, 1), SEV_COLOR[s]))
    t.setStyle(TableStyle(style))
    story.append(t)


def _esc(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _cwe_ref(cwe: str) -> str:
    """CWE-89 → mitre 링크 마크업."""
    import re
    m = re.search(r"(\d+)", cwe or "")
    if not m:
        return _esc(cwe or "-")
    return f'<link href="https://cwe.mitre.org/data/definitions/{m.group(1)}.html" color="#2a5db0">{_esc(cwe)}</link>'


# 위험도별 조치 우선순위(부록·상세 요약용)
_PRIORITY = {"critical": "즉시 조치", "high": "우선 조치", "medium": "계획 조치",
             "low": "참고 개선", "info": "정보성"}
_CRITERIA = {
    "critical": "인증우회·원격코드실행·중요정보 유출 등 즉각적 피해가 가능",
    "high": "권한상승·주입 등 공격 성공 시 영향이 큼",
    "medium": "제한된 조건에서 악용 가능하거나 정보 노출 소지",
    "low": "직접 피해는 낮으나 보안 품질상 개선 권고",
    "info": "취약점은 아니나 참고할 정보",
}
_CRITERIA_EN = {
    "critical": "Immediate impact possible — auth bypass, RCE, sensitive data exposure",
    "high": "High impact if exploited — privilege escalation, injection",
    "medium": "Exploitable under limited conditions, or information exposure",
    "low": "Low direct impact; recommended as security hygiene",
    "info": "Not a vulnerability; informational",
}


def _finding_card(idx, f, SEV, REM, DFT, T, st, en):
    """취약점 1건을 카드형(제목 바 + 항목별 상세)으로."""
    sev = f["severity"]
    color = SEV_COLOR.get(sev, colors.black)
    cwe = f.get("cwe") or ""
    owasp = f.get("owasp") or ""
    title_tail = f'  ({_esc(cwe)}{" · " + _esc(owasp) if owasp else ""})' if cwe or owasp else ""
    title = Paragraph(f'[{SEV.get(sev, sev)}] {idx}. {_esc(f["rule_id"])}{title_tail}', st["cardt"])

    rk = _rule_key(f["rule_id"])
    rem = REM.get(rk, DFT)
    body = st["body"]
    rows = [[title],
            [Paragraph(f'<b>{T("대상")}</b>  <font face="Courier" size=8>{_esc(f["file"])}:{f["line"]}</font>', body)],
            [Paragraph(f'<b>{T("설명")}</b>  {_esc(T(f.get("message", "")))}', body)]]

    steps = f.get("steps") or []
    if steps:
        slabel = STEP_LABEL_EN if en else STEP_LABEL
        parts = []
        for s in steps[:12]:
            k = slabel.get(s.get("kind", ""), s.get("kind", ""))
            parts.append(f'<b>[{_esc(k)}]</b> {_esc(s.get("file", ""))}:{s.get("line", "")}  {_esc((s.get("code") or "").strip())[:160]}')
        rows.append([Paragraph(f'<b>{T("데이터 흐름")}</b>', body)])
        rows.append([Paragraph("<br/>".join(parts), st["flow"])])

    rows.append([Paragraph(f'<b>{T("영향")}</b>  {_esc(rem[1])}', body)])
    rows.append([Paragraph(f'<b>{T("조치 방안")}</b>  {_esc(rem[2])}', body)])
    if rem[3]:
        rows.append([Paragraph(f'<b>{T("안전한 코드 예시")}</b>', body)])
        rows.append([Paragraph(_esc(rem[3]), st["code"])])
    ref = _cwe_ref(cwe) + (f' · OWASP {_esc(owasp)}' if owasp else "")
    rows.append([Paragraph(f'<b>{T("참고")}</b>  {ref}', st["small"])])

    w = 174 * mm
    t = Table(rows, colWidths=[w])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), _FONT),
        ("BACKGROUND", (0, 0), (0, 0), color),
        ("TOPPADDING", (0, 0), (0, 0), 5), ("BOTTOMPADDING", (0, 0), (0, 0), 5),
        ("BOX", (0, 0), (-1, -1), 0.7, color),
        ("LINEBELOW", (0, 0), (0, 0), 0.7, color),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 1), (-1, -1), 3), ("BOTTOMPADDING", (0, 1), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return [KeepTogether(t) if len(rows) <= 8 else t, Spacer(1, 4 * mm)]


def combined_report(scan, path, author: str = "CPGuard", lang: str = "ko",
                    meta: dict | None = None) -> None:
    """합본 진단 결과 보고서 — 표지·개정이력·목차·개요·요약·항목·상세·총평·부록.

    meta: 설정의 보고서 정보(author/org/client/tester/period/version). 비면 기본값."""
    _register_font()
    st = _styles()
    en = lang == "en"
    T = lambda s: tr(s, lang)                       # noqa: E731
    SEV = SEV_EN if en else SEV_KR
    REM = REMEDIATION_EN if en else REMEDIATION
    DFT = DEFAULT_REM_EN if en else _DEFAULT_REM
    CRIT = _CRITERIA_EN if en else _CRITERIA
    meta = meta or {}
    author = meta.get("author") or author
    version = meta.get("version") or "1.0"
    findings = scan.findings
    counts = scan.severity_counts
    total = len(findings)
    project = scan.project or Path(scan.name).stem
    today = _dt.date.today().strftime("%Y-%m-%d")
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    story: list = []

    # ── 표지 ── (설정에 있는 항목만 추가로 표기)
    cover_rows = [(T("프로젝트"), project), (T("대상"), scan.name)]
    if meta.get("client"):
        cover_rows.append((T("발주처/고객"), meta["client"]))
    if meta.get("org"):
        cover_rows.append((T("수행 기관/회사"), meta["org"]))
    cover_rows += [(T("분석 도구"), T("CPGuard (CPG 기반 taint 분석)")),
                   (T("분석 일시"), scan.created_at.strftime("%Y-%m-%d %H:%M"))]
    if meta.get("period"):
        cover_rows.append((T("진단 수행 기간"), meta["period"]))
    cover_rows += [(T("소스 파일 수"), str(scan.file_count)), (T("총 이슈"), str(total)),
                   (T("작성일"), today), (T("작성자"), author)]
    if meta.get("tester"):
        cover_rows.append((T("진단 담당자"), meta["tester"]))
    cover_rows.append((T("보고서 버전"), version))
    _cover(story, st, f"{project}\n" + T("소스코드 취약점 진단 결과 보고서"),
           T("SAST 진단 · CPGuard"), cover_rows)

    # ── 문서 개정 이력 ──
    story.append(Paragraph(T("문서 개정 이력"), st["h2"]))   # h2(목차 미등록) — 목차엔 안 넣는다
    rev = [[T("버전"), T("일자"), T("내용"), T("작성")],
           [version, today, T("최초 작성"), author]]
    rt = Table(rev, colWidths=[20 * mm, 30 * mm, 96 * mm, 28 * mm])
    rt.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6")),
        ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dae2")),
        ("ALIGN", (0, 0), (1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(rt)
    story.append(PageBreak())

    # ── 목차 ──
    story.append(Paragraph(T("목차"), st["h1"]))
    toc = TableOfContents()
    toc.levelStyles = [
        ParagraphStyle("toc0", fontName=_FONT_B, fontSize=10.5, leading=20, textColor=colors.HexColor("#22314f")),
        ParagraphStyle("toc1", fontName=_FONT, fontSize=9.5, leading=16, leftIndent=14, textColor=colors.HexColor("#444")),
    ]
    story.append(toc)
    story.append(PageBreak())

    # ── 1. 진단 개요 ──
    story.append(Paragraph(T("1. 진단 개요"), st["h1"]))
    story.append(Paragraph(T("1.1 진단 배경 및 목적"), st["h2sec"]))
    story.append(Paragraph(T(
        "본 보고서는 대상 소스코드에 대해 CPGuard 정적 분석(데이터 흐름 taint 분석 + 패턴 점검)을 "
        "수행하여 도출한 보안약점과 그 조치 방안을 기술한다. 각 취약점은 CWE·OWASP 기준으로 분류하고, "
        "위험도에 따라 조치 우선순위를 제시한다."), st["body"]))
    story.append(Spacer(1, 3 * mm))
    langs = ", ".join(sorted({Path(f["file"]).suffix.lstrip(".").lower() for f in findings if f.get("file")}) or ["-"])
    story.append(Paragraph(T("1.2 진단 대상 범위"), st["h2sec"]))
    story.append(_kv_table([
        ("프로젝트", project), ("대상", scan.name),
        ("대상 파일 수", str(scan.file_count)), ("탐지 이슈 수", str(total)),
        ("분석 언어", langs),
    ], T))
    story.append(Spacer(1, 3 * mm))
    story.append(Paragraph(T("1.3 진단 방법 및 기준"), st["h2sec"]))
    story.append(_kv_table([
        ("진단 도구", T("CPGuard (CPG 기반 taint 분석 + 패턴)")),
        ("진단 기준", "CWE · OWASP Top 10"),
        ("진단 일시", scan.created_at.strftime("%Y-%m-%d %H:%M")),
    ], T))
    if scan.integrity_note:
        note = ("* Partial coverage — some files could not be fully analyzed; results may not "
                "represent the whole." if en else "* " + scan.integrity_note)
        story.append(Spacer(1, 2 * mm))
        story.append(Paragraph(f'<font color="#a33">{_esc(note)}</font>', st["small"]))
    story.append(PageBreak())

    # ── 2. 진단 결과 요약 ──
    story.append(Paragraph(T("2. 진단 결과 요약"), st["h1"]))
    _severity_table(story, st, counts, SEV, T)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(T("위험도 분포"), st["h2sec"]))
    story.append(_sev_chart(counts, SEV))
    story.append(Spacer(1, 4 * mm))
    # CWE 상위
    cwe_c: dict = {}
    seen: dict = {}
    for f in findings:
        c = f.get("cwe") or "-"
        cwe_c[c] = cwe_c.get(c, 0) + 1
        seen.setdefault(c, f.get("rule_id"))
    story.append(Paragraph(T("취약점 유형(CWE) 상위"), st["h2sec"]))
    rows = [["CWE", T("규칙 예"), T("개수")]]
    for cwe, n in sorted(cwe_c.items(), key=lambda x: -x[1])[:12]:
        rows.append([cwe, seen.get(cwe, ""), str(n)])
    ct = Table(rows, colWidths=[36 * mm, 118 * mm, 20 * mm])
    ct.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 9),
                            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dae2")),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6")),
                            ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
                            ("ALIGN", (2, 0), (2, -1), "CENTER"),
                            ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(ct)

    # ── 진단 이력 — 같은 프로젝트를 N 회 돌린 경우 최근→과거 표. 각 회차의 신규/해결로
    #    이전 대비 증감을 보여준다(해결된 취약점은 최신 회차 건수에서 이미 빠져 있다).
    Scan = scan.__class__
    runs = list(Scan.objects.filter(project=scan.project).order_by("-created_at")) if scan.project else [scan]
    total_runs = len(runs)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(T("진단 이력"), st["h2sec"]))
    cur_idx = next((i for i, r in enumerate(runs) if r.pk == scan.pk), 0)
    if en:
        lead = (f"This project has been assessed {total_runs} time(s). Runs are listed latest first; "
                f"'New'/'Resolved' are relative to the immediately preceding run.")
    else:
        lead = (f"이 프로젝트는 총 {total_runs}회 진단되었다. 최근 회차부터 나열하며, "
                f"신규/해결은 직전 회차 대비 증감이다(해결된 취약점은 해당 회차 건수에서 이미 제외됨).")
    story.append(Paragraph(lead, st["body"]))
    story.append(Spacer(1, 2 * mm))
    hrows = [[T("회차"), T("일시"), T("탐지"), T("신규"), T("해결")] + [SEV.get(s, s) for s in SEV_ORDER]]
    for i, r in enumerate(runs):
        no = total_runs - i
        mark = " ◀" if r.pk == scan.pk else ""
        hrows.append([f"{no}{mark}", r.created_at.strftime("%Y-%m-%d %H:%M"), str(r.finding_count),
                      f"+{r.new_count}" if r.new_count else "0",
                      f"-{r.resolved_count}" if r.resolved_count else "0",
                      str(r.sev_critical), str(r.sev_high), str(r.sev_medium), str(r.sev_low), str(r.sev_info)])
    ht = Table(hrows, colWidths=[14 * mm, 30 * mm, 16 * mm, 16 * mm, 16 * mm] + [16.4 * mm] * 5, repeatRows=1)
    hstyle = [("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
              ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dae2")),
              ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6")),
              ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
              ("ALIGN", (2, 0), (-1, -1), "CENTER"), ("ALIGN", (0, 0), (0, -1), "CENTER"),
              ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
              ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]
    # 현재 보고서 회차 행 강조
    hstyle.append(("BACKGROUND", (0, cur_idx + 1), (-1, cur_idx + 1), colors.HexColor("#f7f7f7")))
    hstyle.append(("FONTNAME", (0, cur_idx + 1), (-1, cur_idx + 1), _FONT_B))
    for j, s in enumerate(SEV_ORDER, 5):
        hstyle.append(("TEXTCOLOR", (j, 1), (j, -1), SEV_COLOR[s]))
    ht.setStyle(TableStyle(hstyle))
    story.append(ht)
    prev = scan.previous()
    if prev is not None:
        delta = scan.finding_count - prev.finding_count
        if en:
            note = (f"vs previous run: {'+' if delta > 0 else ''}{delta} findings "
                    f"(new +{scan.new_count}, resolved -{scan.resolved_count}).")
        else:
            note = (f"이전 대비: 탐지 {'+' if delta > 0 else ''}{delta}건 "
                    f"(신규 +{scan.new_count} · 해결 -{scan.resolved_count}).")
        story.append(Spacer(1, 1.5 * mm))
        story.append(Paragraph(note, st["small"]))
    story.append(PageBreak())

    # ── 3. 진단 항목 ──
    story.append(Paragraph(T("3. 진단 항목"), st["h1"]))
    story.append(Paragraph(T(
        "이번 진단에서 탐지된 점검 항목(규칙)과 분류·건수는 다음과 같다."), st["body"]))
    story.append(Spacer(1, 2 * mm))
    by_rule: dict = {}
    for f in findings:
        r = f["rule_id"]
        d = by_rule.setdefault(r, {"cwe": f.get("cwe", ""), "n": 0})
        d["n"] += 1
    irows = [[T("점검 항목"), "CWE", T("탐지")]]
    for r, d in sorted(by_rule.items(), key=lambda x: -x[1]["n"]):
        irows.append([r, d["cwe"] or "-", str(d["n"])])
    it = Table(irows, colWidths=[124 * mm, 32 * mm, 18 * mm], repeatRows=1)
    it.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dae2")),
                            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6")),
                            ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
                            ("ALIGN", (2, 0), (2, -1), "CENTER"),
                            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story.append(it)
    story.append(PageBreak())

    # ── 4. 상세 진단 결과 ──
    story.append(Paragraph(T("4. 상세 진단 결과"), st["h1"]))
    CAP = 200
    ordered = sorted(findings, key=lambda x: (order.get(x["severity"], 9), x.get("file", ""), x.get("line", 0)))
    shown = ordered[:CAP]
    if total > CAP:
        note = (f"Showing the top {CAP} findings by severity; see the analysis sheet (xlsx) for all {total}."
                if en else f"위험도 상위 {CAP}건을 상세 기술하며, 전체 {total}건은 분석목록표(xlsx)를 참조한다.")
        story.append(Paragraph(f'<font color="#a33">* {note}</font>', st["small"]))
        story.append(Spacer(1, 2 * mm))
    for i, f in enumerate(shown, 1):
        for fl in _finding_card(i, f, SEV, REM, DFT, T, st, en):
            story.append(fl)

    # ── 5. 종합 의견 ──
    story.append(PageBreak())
    story.append(Paragraph(T("5. 종합 의견"), st["h1"]))
    ch = counts.get("critical", 0) + counts.get("high", 0)
    if en:
        summary = (f"A total of {total} security weaknesses were identified, of which {ch} are "
                   f"Critical/High severity requiring immediate action. Prioritize Critical/High "
                   f"items, then apply input validation, output encoding, secret separation and "
                   f"safe algorithms per the remediation for each type.")
    else:
        summary = (f"총 {total}건의 보안약점이 도출되었으며, 이 중 즉시 조치가 필요한 매우위험·위험 "
                   f"등급이 {ch}건이다. 매우위험·위험 항목을 우선 조치하고, 유형별 조치 방안에 따라 "
                   f"입력 검증·출력 인코딩·비밀정보 분리·안전한 알고리즘 적용을 권고한다.")
    story.append(Paragraph(summary, st["body"]))

    # ── 부록 A. 위험도 판정 기준 ──
    story.append(Spacer(1, 6 * mm))
    story.append(Paragraph(T("부록 A. 위험도 판정 기준"), st["h1"]))
    arows = [[T("판정"), T("기준"), T("조치 우선순위")]]
    for s in SEV_ORDER:
        arows.append([SEV.get(s, s), CRIT[s], T(_PRIORITY[s])])
    at = Table(arows, colWidths=[28 * mm, 118 * mm, 28 * mm])
    astyle = [("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 9),
              ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#d5dae2")),
              ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eef1f6")),
              ("FONTNAME", (0, 0), (-1, 0), _FONT_B),
              ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
              ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]
    for i, s in enumerate(SEV_ORDER, 1):
        astyle.append(("TEXTCOLOR", (0, i), (0, i), SEV_COLOR[s]))
        astyle.append(("FONTNAME", (0, i), (0, i), _FONT_B))
    at.setStyle(TableStyle(astyle))
    story.append(at)

    _build_report(story, path, f"{project} " + T("진단 결과 보고서"))


def remediation_guide(scan, path, lang: str = "ko", meta: dict | None = None) -> None:
    """유형별 조치 가이드 — 스캔에 등장한 규칙 유형별 설명·조치·예시."""
    _register_font()
    st = _styles()
    en = lang == "en"
    T = lambda s: tr(s, lang)                       # noqa: E731
    REM = REMEDIATION_EN if en else REMEDIATION
    DFT = DEFAULT_REM_EN if en else _DEFAULT_REM
    meta = meta or {}
    findings = scan.findings
    project = scan.project or Path(scan.name).stem

    # rule_id 별 집계
    by_rule: dict = {}
    for f in findings:
        by_rule.setdefault(f["rule_id"], {"cwe": f.get("cwe", ""), "owasp": f.get("owasp", ""),
                                          "msg": f.get("message", ""), "files": []})
        by_rule[f["rule_id"]]["files"].append(f'{f["file"]}:{f["line"]}')

    story = []
    grows = [(T("프로젝트"), project), (T("대상"), scan.name)]
    if meta.get("client"):
        grows.append((T("발주처/고객"), meta["client"]))
    if meta.get("org"):
        grows.append((T("수행 기관/회사"), meta["org"]))
    grows += [(T("작성일"), _dt.date.today().strftime("%Y-%m-%d")),
              (T("탐지 유형"), f"{len(by_rule)} types" if en else f"{len(by_rule)}종"),
              (T("총 이슈"), str(len(findings))),
              (T("작성자"), meta.get("author") or "CPGuard")]
    _cover(story, st, f"{project}\n" + T("보안약점 조치 가이드"), T("유형별 설명 · 조치 방법 · 안전 예시"), grows)

    for idx, (rid, info) in enumerate(sorted(by_rule.items(), key=lambda x: -len(x[1]["files"])), 1):
        rk = _rule_key(rid)
        rem = REM.get(rk, DFT)
        cnt = len(info["files"])
        cnt_lbl = f"{cnt}" if en else f"{cnt}건"
        story.append(Paragraph(f"{idx}. {rem[0]} <font size=9 color='#888'>({rid} · {cnt_lbl})</font>", st["h1"]))
        story.append(Paragraph(f'<b>CWE:</b> {info["cwe"] or "-"} &nbsp;&nbsp; <b>OWASP:</b> {info["owasp"] or "-"}', st["small"]))
        story.append(Paragraph(f'<b>{T("설명")}.</b> {rem[1]}', st["body"]))
        story.append(Paragraph(f'<b>{T("조치 방법")}.</b> {rem[2]}', st["body"]))
        if rem[3]:
            story.append(Paragraph(T("안전 예시:"), st["small"]))
            story.append(Paragraph(rem[3].replace("<", "&lt;"), st["code"]))
        # 해당 위치(최대 8개)
        more = (f" +{cnt - 8} more" if en else f" 외 {cnt - 8}건") if cnt > 8 else ""
        locs = ", ".join(info["files"][:8]) + more
        story.append(Paragraph(f'<b>{T("해당 위치")}.</b> <font face="Courier" size=8>{locs}</font>', st["small"]))
        story.append(Spacer(1, 5 * mm))

    _build(story, path, f"{project} " + T("조치 가이드"))


def _footer(canvas, doc):
    if doc.page <= 1:          # 표지엔 쪽번호 없음
        return
    canvas.saveState()
    canvas.setFont(_FONT, 8)
    canvas.setFillColor(colors.HexColor("#999"))
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"{doc.page}")
    canvas.drawString(18 * mm, 12 * mm, "CPGuard")
    canvas.restoreState()


class _SectionDoc(BaseDocTemplate):
    """h1/h2sec 문단을 목차 항목으로 등록하는 문서(TableOfContents 용). multiBuild 필요."""

    def __init__(self, filename, title):
        frame = Frame(18 * mm, 18 * mm, A4[0] - 36 * mm, A4[1] - 36 * mm, id="body")
        super().__init__(filename, pagesize=A4, title=title,
                         leftMargin=18 * mm, rightMargin=18 * mm,
                         topMargin=18 * mm, bottomMargin=18 * mm)
        self.addPageTemplates([PageTemplate(id="main", frames=[frame], onPage=_footer)])

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph):
            name = flowable.style.name
            if name == "h1":
                self.notify("TOCEntry", (0, flowable.getPlainText(), self.page))
            elif name == "h2sec":
                self.notify("TOCEntry", (1, flowable.getPlainText(), self.page))


def _build_report(story, path, title):
    """목차 쪽번호를 위해 두 번 빌드(multiBuild)."""
    _SectionDoc(str(path), title).multiBuild(story)


def _build(story, path, title):
    doc = SimpleDocTemplate(str(path), pagesize=A4, title=title,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm)
    doc.build(story, onLaterPages=_footer, onFirstPage=lambda c, d: None)
