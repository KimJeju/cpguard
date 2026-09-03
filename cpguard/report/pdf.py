"""PDF 산출 — 합본 진단 결과 보고서 · 유형별 조치 가이드.

reportlab(순수 파이썬, 번들 가능) + 시스템 맑은고딕(Windows). 폰트가 없으면
Helvetica 로 폴백(한글이 깨지므로 Windows 대상에선 malgun.ttf 를 쓴다).
"""
from __future__ import annotations

import datetime as _dt
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (PageBreak, Paragraph, SimpleDocTemplate, Spacer,
                                Table, TableStyle)

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
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], fontName=_FONT_B, fontSize=15, spaceBefore=10, spaceAfter=8)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName=_FONT_B, fontSize=12, spaceBefore=10, spaceAfter=5)
    small = ParagraphStyle("small", parent=body, fontSize=8.5, textColor=colors.HexColor("#555"))
    code = ParagraphStyle("code", parent=body, fontName="Courier", fontSize=8.5, textColor=colors.HexColor("#0a3"),
                          backColor=colors.HexColor("#f4f4f4"), borderPadding=4)
    return {"body": body, "h1": h1, "h2": h2, "small": small, "code": code}


def _cover(story, st, title, subtitle, meta_rows):
    center = ParagraphStyle("cvc", parent=st["body"], alignment=TA_CENTER)
    story.append(Spacer(1, 45 * mm))
    story.append(Paragraph("SOURCE CODE SECURITY ASSESSMENT", ParagraphStyle("c0", parent=center, fontName=_FONT, fontSize=11, textColor=colors.HexColor("#888"))))
    story.append(Spacer(1, 8 * mm))
    story.append(Paragraph(title, ParagraphStyle("c1", parent=center, fontName=_FONT_B, fontSize=22, leading=30)))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(subtitle, ParagraphStyle("c2", parent=center, fontName=_FONT, fontSize=13, textColor=colors.HexColor("#444"))))
    story.append(Spacer(1, 30 * mm))
    t = Table([[k, v] for k, v in meta_rows], colWidths=[45 * mm, 90 * mm])
    t.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#666")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6), ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#ddd")),
    ]))
    story.append(t)
    story.append(PageBreak())


def _severity_table(story, st, counts):
    total = sum(counts.get(s, 0) for s in SEV_ORDER)
    head = ["위험도"] + [SEV_KR[s] for s in SEV_ORDER] + ["합계"]
    row = ["개수"] + [str(counts.get(s, 0)) for s in SEV_ORDER] + [str(total)]
    t = Table([head, row], colWidths=[24 * mm] + [22 * mm] * 5 + [22 * mm])
    style = [("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 9),
             ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#ccc")),
             ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
             ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
             ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5)]
    for i, s in enumerate(SEV_ORDER, 1):
        style.append(("TEXTCOLOR", (i, 1), (i, 1), SEV_COLOR[s]))
    t.setStyle(TableStyle(style))
    story.append(t)


def combined_report(scan, path, author: str = "CPGuard") -> None:
    """합본 진단 결과 보고서."""
    _register_font()
    st = _styles()
    findings = scan.findings
    counts = scan.severity_counts
    project = scan.project or Path(scan.name).stem
    story = []

    _cover(story, st, f"{project}\n소스코드 취약점 진단 결과 보고서",
           "SAST 진단 · CPGuard",
           [("프로젝트", project), ("대상", scan.name),
            ("분석 도구", "CPGuard (CPG 기반 taint 분석)"),
            ("분석 일시", scan.created_at.strftime("%Y-%m-%d %H:%M")),
            ("소스 파일 수", str(scan.file_count)), ("총 이슈", str(len(findings))),
            ("작성일", _dt.date.today().strftime("%Y-%m-%d")), ("작성자", author)])

    story.append(Paragraph("1. 진단 개요", st["h1"]))
    story.append(Paragraph(
        "본 보고서는 CPGuard 정적 분석(데이터 흐름 taint + 패턴)을 통해 대상 소스코드의 "
        "보안약점을 도출한 결과이다. 각 이슈는 CWE·OWASP 로 분류되며, 유형별 조치 방법은 "
        "별도의 조치 가이드를 참조한다.", st["body"]))
    story.append(Spacer(1, 4 * mm))

    story.append(Paragraph("2. 위험도별 진단 결과", st["h1"]))
    _severity_table(story, st, counts)
    story.append(Spacer(1, 5 * mm))

    story.append(Paragraph("3. 레퍼런스별(CWE) 집계", st["h1"]))
    cwe_c: dict = {}
    for f in findings:
        cwe_c[f.get("cwe") or "-"] = cwe_c.get(f.get("cwe") or "-", 0) + 1
    rows = [["CWE", "규칙 예", "개수"]]
    seen: dict = {}
    for f in findings:
        seen.setdefault(f.get("cwe") or "-", f.get("rule_id"))
    for cwe, n in sorted(cwe_c.items(), key=lambda x: -x[1]):
        rows.append([cwe, seen.get(cwe, ""), str(n)])
    t = Table(rows, colWidths=[35 * mm, 75 * mm, 20 * mm])
    t.setStyle(TableStyle([("FONTNAME", (0, 0), (-1, -1), _FONT), ("FONTSIZE", (0, 0), (-1, -1), 9),
                           ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#ccc")),
                           ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f0f0f0")),
                           ("ALIGN", (2, 0), (2, -1), "CENTER"),
                           ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4)]))
    story.append(t)
    story.append(PageBreak())

    story.append(Paragraph("4. 상세 결과", st["h1"]))
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    for i, f in enumerate(sorted(findings, key=lambda x: order.get(x["severity"], 9)), 1):
        sev = f["severity"]
        story.append(Paragraph(
            f'<font color="{SEV_COLOR.get(sev, colors.black)}"><b>[{SEV_KR.get(sev, sev)}]</b></font> '
            f'{i}. {f["rule_id"]} <font size=8 color="#888">({f.get("cwe","")}{" · " + f["owasp"] if f.get("owasp") else ""})</font>',
            st["h2"]))
        story.append(Paragraph(f'위치: <font face="Courier">{f["file"]}:{f["line"]}</font>', st["small"]))
        story.append(Paragraph(f.get("message", ""), st["body"]))
        rk = _rule_key(f["rule_id"])
        rem = REMEDIATION.get(rk, _DEFAULT_REM)
        story.append(Paragraph(f'<b>조치:</b> {rem[2]}', st["body"]))
        story.append(Spacer(1, 3 * mm))

    story.append(PageBreak())
    story.append(Paragraph("5. 총평", st["h1"]))
    ch = counts.get("critical", 0) + counts.get("high", 0)
    story.append(Paragraph(
        f"총 {len(findings)}건의 보안약점이 도출되었으며, 이 중 즉시 조치가 필요한 매우위험·위험 "
        f"등급이 {ch}건이다. 매우위험·위험 항목을 우선 조치하고, 유형별 조치 가이드에 따라 "
        f"입력 검증·출력 인코딩·비밀정보 분리·안전한 알고리즘 적용을 권고한다.", st["body"]))

    _build(story, path, f"{project} 진단 결과 보고서")


def remediation_guide(scan, path) -> None:
    """유형별 조치 가이드 — 스캔에 등장한 규칙 유형별 설명·조치·예시."""
    _register_font()
    st = _styles()
    findings = scan.findings
    project = scan.project or Path(scan.name).stem

    # rule_id 별 집계
    by_rule: dict = {}
    for f in findings:
        by_rule.setdefault(f["rule_id"], {"cwe": f.get("cwe", ""), "owasp": f.get("owasp", ""),
                                          "msg": f.get("message", ""), "files": []})
        by_rule[f["rule_id"]]["files"].append(f'{f["file"]}:{f["line"]}')

    story = []
    _cover(story, st, f"{project}\n보안약점 조치 가이드", "유형별 설명 · 조치 방법 · 안전 예시",
           [("프로젝트", project), ("대상", scan.name), ("작성일", _dt.date.today().strftime("%Y-%m-%d")),
            ("탐지 유형", f"{len(by_rule)}종"), ("총 이슈", str(len(findings)))])

    for idx, (rid, info) in enumerate(sorted(by_rule.items(), key=lambda x: -len(x[1]["files"])), 1):
        rk = _rule_key(rid)
        rem = REMEDIATION.get(rk, _DEFAULT_REM)
        story.append(Paragraph(f"{idx}. {rem[0]} <font size=9 color='#888'>({rid} · {len(info['files'])}건)</font>", st["h1"]))
        story.append(Paragraph(f'<b>CWE:</b> {info["cwe"] or "-"} &nbsp;&nbsp; <b>OWASP:</b> {info["owasp"] or "-"}', st["small"]))
        story.append(Paragraph(f'<b>설명.</b> {rem[1]}', st["body"]))
        story.append(Paragraph(f'<b>조치 방법.</b> {rem[2]}', st["body"]))
        if rem[3]:
            story.append(Paragraph("안전 예시:", st["small"]))
            story.append(Paragraph(rem[3].replace("<", "&lt;"), st["code"]))
        # 해당 위치(최대 8개)
        locs = ", ".join(info["files"][:8]) + (f" 외 {len(info['files']) - 8}건" if len(info["files"]) > 8 else "")
        story.append(Paragraph(f'<b>해당 위치.</b> <font face="Courier" size=8>{locs}</font>', st["small"]))
        story.append(Spacer(1, 5 * mm))

    _build(story, path, f"{project} 조치 가이드")


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont(_FONT, 8)
    canvas.setFillColor(colors.HexColor("#999"))
    canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"{doc.page}")
    canvas.drawString(18 * mm, 12 * mm, "CPGuard")
    canvas.restoreState()


def _build(story, path, title):
    doc = SimpleDocTemplate(str(path), pagesize=A4, title=title,
                            leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=18 * mm, bottomMargin=18 * mm)
    doc.build(story, onLaterPages=_footer, onFirstPage=lambda c, d: None)
