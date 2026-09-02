"""대시보드 뷰 — zip 업로드 → 안전해제 → 스캔 → 감사 작업대."""
from __future__ import annotations

import csv
import json
import shutil
import tempfile
from pathlib import Path

from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from ..extract import UnsafeArchive, safe_extract_zip
from ..report.finding import Finding
from ..report.sarif import to_sarif
from ..scanner import scan_path
from .models import Scan

# 코드 뷰어용 원본 보관 한도 (DB 비대화 방지)
MAX_SOURCE_BYTES = 200_000
MAX_SOURCES_TOTAL = 8_000_000

AUDIT_STATES = ("", "confirmed", "false_positive", "fixed", "deferred")


def _base_context() -> dict:
    from ..triage import available
    scans = list(Scan.objects.all()[:60])
    # 프로젝트별 최신 스캔만 — 홈 목록은 프로젝트 단위로 보여준다
    latest: dict[str, Scan] = {}
    for s in scans:
        key = s.project or s.name
        if key not in latest:
            latest[key] = s
    return {"scans": scans[:30], "projects": list(latest.values()), "providers": available()}


def _fingerprint(f: Finding, rel_file: str) -> str:
    """스캔 간 같은 이슈를 잇는 지문. 줄 번호는 넣지 않는다 — 위에 코드가 추가되면 밀리므로.

    규칙 + 파일 + 위험 지점 코드(공백 정규화) 로 만든다. 같은 파일에 같은 sink 가 두 번
    있으면 하나로 묶이는 한계가 있지만, 신규/해결 판정에는 이쪽이 더 안정적이다.
    """
    import hashlib
    # 공백은 전부 버린다: 포맷터가 띄어쓰기를 바꿔도 같은 이슈여야 한다
    code = "".join(f.sink.code.split())
    return hashlib.sha1(f"{f.rule_id}|{rel_file}|{code}".encode("utf-8")).hexdigest()[:16]


def _project_of(filename: str) -> str:
    """업로드 파일명 → 프로젝트 이름. 'app-main.zip' / 'app-v2.zip' 은 같은 프로젝트로 본다."""
    import re
    stem = Path(filename).stem
    stem = re.sub(r"[-_ ](?:main|master|dev|develop|v?\d+(?:\.\d+)*|\d{8}|\d{6})$", "", stem, flags=re.I)
    return stem.strip() or Path(filename).stem


def _rel(path: str, base: Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(base)).replace("\\", "/")
    except Exception:
        return Path(path).name


def _finding_to_dict(idx: int, f: Finding, base: Path) -> dict:
    return {
        "id": idx,
        "rule_id": f.rule_id,
        "message": f.message,
        "severity": f.severity,
        "cwe": f.cwe,
        "owasp": f.owasp,
        "file": _rel(f.sink.loc.file, base),
        "line": f.sink.loc.start_line,
        "verdict": f.verdict,
        "confidence": f.confidence,
        "triage_reason": f.triage_reason,
        "triage_provider": f.triage_provider,
        "precision": f.precision,
        "fp_hint": f.fp_hint,
        "matched_value": f.matched_value,
        "category": f.category,
        "fp": _fingerprint(f, _rel(f.sink.loc.file, base)),
        "steps": [
            {"kind": s.kind, "file": _rel(s.loc.file, base),
             "line": s.loc.start_line, "code": s.code}
            for s in f.steps
        ],
    }


def _collect_sources(findings: list[Finding], base: Path) -> dict[str, str]:
    """탐지가 있는 파일의 원본만 모은다 — 코드 뷰어가 흐름을 원문 위에 표시하도록."""
    wanted: set[str] = set()
    for f in findings:
        for s in f.steps:
            wanted.add(s.loc.file)

    out: dict[str, str] = {}
    total = 0
    for abs_path in sorted(wanted):
        p = Path(abs_path)
        try:
            if not p.is_file() or p.stat().st_size > MAX_SOURCE_BYTES:
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        total += len(text)
        if total > MAX_SOURCES_TOTAL:
            break
        out[_rel(abs_path, base)] = text
    return out


def index(request):
    return render(request, "index.html", _base_context())


def upload(request):
    if request.method != "POST":
        return redirect("index")

    up = request.FILES.get("archive")
    if not up:
        return render(request, "index.html",
                      {**_base_context(), "error": "zip 파일을 선택하세요."})
    if not up.name.lower().endswith(".zip"):
        return render(request, "index.html",
                      {**_base_context(), "error": "zip 파일만 지원합니다."})

    workdir = Path(tempfile.mkdtemp(prefix="cpguard_"))
    try:
        zip_path = workdir / "upload.zip"
        with open(zip_path, "wb") as fh:
            for chunk in up.chunks():
                fh.write(chunk)

        src_dir = workdir / "src"
        try:
            safe_extract_zip(zip_path, src_dir)
        except UnsafeArchive as e:
            return render(request, "index.html", {
                **_base_context(),
                "error": f"안전하지 않은 아카이브라 거부했습니다 — {e}",
            })

        findings, scan_report = scan_path(src_dir)
        base = src_dir.resolve()

        integrity_note = "" if scan_report.complete else scan_report.summary()
        triage_note = ""
        if request.POST.get("triage") and findings:
            from ..triage import TriageUnavailable, triage_findings
            try:
                triage_findings(findings, provider=request.POST.get("provider") or None)
            except TriageUnavailable as e:
                triage_note = f"LLM 트리아지를 건너뛰었습니다 — {e}"

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (order.get(f.severity, 9), f.rule_id))

        project = request.POST.get("project", "").strip() or _project_of(up.name)
        scan = Scan.objects.create(
            name=up.name,
            project=project,
            file_count=scan_report.scanned,
            finding_count=len(findings),
            findings_json=json.dumps(
                [_finding_to_dict(i, f, base) for i, f in enumerate(findings)],
                ensure_ascii=False),
            sarif_json=json.dumps(to_sarif(findings, base), ensure_ascii=False),
            sources_json=json.dumps(_collect_sources(findings, base), ensure_ascii=False),
            triage_note=triage_note,
            integrity_note=integrity_note,
        )
        # 이전 스캔 대비 신규/해결 — 지문 기준
        prev = scan.previous()
        if prev is not None:
            diff = scan.compare_with(prev)
            scan.new_count = len(diff["new"])
            scan.resolved_count = len(diff["resolved"])
            scan.save(update_fields=["new_count", "resolved_count"])
        return redirect("detail", pk=scan.pk)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def detail(request, pk: int):
    """감사 작업대 — 좌: 이슈 트리, 중앙: 코드 뷰어, 우: 상세/흐름."""
    scan = get_object_or_404(Scan, pk=pk)
    findings = scan.findings
    audit = scan.audit
    for f in findings:
        f["audit"] = audit.get(str(f["id"]), "")

    # 이전 스캔 대비 신규 여부를 각 이슈에 표시 (조사 우선순위의 첫 번째 신호)
    prev = scan.previous()
    new_fps = scan.compare_with(prev)["new_fps"] if prev else set()
    for f in findings:
        f["is_new"] = bool(prev) and f.get("fp") in new_fps

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["file"], f["line"]))

    return render(request, "workbench.html", {
        "scan": scan,
        "prev": prev,
        # 소스 원문에는 </script> 같은 문자열이 들어있을 수 있다.
        # 템플릿에서 json_script 필터로 내보내 스크립트 태그 탈출을 막는다.
        "findings": findings,
        "sources": scan.sources,
        "counts": scan.severity_counts,
        "rule_counts": scan.rule_counts,
        "file_counts": scan.file_counts[:40],
        "total": len(findings),
    })


def project_home(request, name: str):
    """프로젝트 홈 — '지금 안전한가 / 뭐가 새로 생겼나 / 뭘 먼저 봐야 하나' 에 즉시 답한다.

    대시보드가 아니라 조사 시작점이다: 우선 조사 대상을 한 번의 클릭으로 열 수 있어야 한다.
    """
    scans = list(Scan.objects.filter(project=name).order_by("-created_at"))
    if not scans:
        return redirect("index")
    latest = scans[0]
    prev = scans[1] if len(scans) > 1 else None
    diff = latest.compare_with(prev) if prev else {"new": [], "resolved": [], "new_fps": set()}
    audit = latest.audit
    new_fps = diff["new_fps"]

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    # 우선 조사: 감사 안 된 것 중 신규 → 위험도 순
    priority = [f for f in latest.findings if not audit.get(str(f["id"]))]
    priority.sort(key=lambda f: (0 if f.get("fp") in new_fps else 1,
                                 sev_order.get(f["severity"], 9), f["file"]))

    # 추세: 오래된 것 → 최신 (최대 12회)
    trend = [{"pk": s.pk, "when": s.created_at, "total": s.finding_count,
              "counts": s.severity_counts, "new": s.new_count, "resolved": s.resolved_count}
             for s in reversed(scans[:12])]
    risk_delta = (latest.finding_count - prev.finding_count) if prev else 0

    return render(request, "project_home.html", {
        "project": name,
        "latest": latest,
        "prev": prev,
        "counts": latest.severity_counts,
        "priority": priority[:8],
        "new_count": len(diff["new"]),
        "resolved_count": len(diff["resolved"]),
        "new_fps": new_fps,
        "risk_delta": risk_delta,
        "trend": trend,
        "trend_max": max((t["total"] for t in trend), default=1) or 1,
        "scans": scans,
        "audited": sum(1 for f in latest.findings if audit.get(str(f["id"]))),
    })


@require_POST
def set_audit(request, pk: int):
    """사람이 확정한 감사 결과 저장 (Fortify 의 analysis 필드에 해당)."""
    scan = get_object_or_404(Scan, pk=pk)
    try:
        idx = int(request.POST.get("index", ""))
    except ValueError:
        return JsonResponse({"ok": False, "error": "잘못된 index"}, status=400)
    status = request.POST.get("status", "")
    if status not in AUDIT_STATES:
        return JsonResponse({"ok": False, "error": "알 수 없는 상태"}, status=400)
    scan.set_audit(idx, status)
    return JsonResponse({"ok": True, "index": idx, "status": status})


@require_POST
def ai_ask(request, pk: int):
    """AI 분석 패널 — 현재 선택된 이슈의 맥락(규칙·흐름·주변 코드)을 자동으로 붙여 묻는다.

    키가 없으면 실패가 아니라 안내를 돌려준다(트리아지와 같은 원칙: 부가 기능).
    """
    from ..triage import PRESETS, TriageUnavailable, ask
    scan = get_object_or_404(Scan, pk=pk)
    try:
        idx = int(request.POST.get("index", ""))
    except ValueError:
        return JsonResponse({"ok": False, "error": "잘못된 index"}, status=400)
    findings = scan.findings
    if not (0 <= idx < len(findings)):
        return JsonResponse({"ok": False, "error": "없는 이슈"}, status=404)
    finding = findings[idx]
    finding["audit"] = scan.audit.get(str(idx), "")
    preset = request.POST.get("preset", "explain")
    if preset not in PRESETS and not request.POST.get("question"):
        return JsonResponse({"ok": False, "error": "알 수 없는 프리셋"}, status=400)
    try:
        answer, provider = ask(
            finding, scan.sources, preset=preset,
            question=request.POST.get("question") or None,
            provider=request.POST.get("provider") or None,
        )
    except TriageUnavailable as e:
        return JsonResponse({"ok": False, "unavailable": True, "error": str(e)})
    except Exception as e:  # 프로바이더 오류는 패널에 그대로 보여준다
        return JsonResponse({"ok": False, "error": f"{type(e).__name__}: {e}"})
    return JsonResponse({"ok": True, "answer": answer, "provider": provider, "preset": preset})


def sarif_download(request, pk: int):
    scan = get_object_or_404(Scan, pk=pk)
    resp = HttpResponse(scan.sarif_json, content_type="application/json")
    resp["Content-Disposition"] = f'attachment; filename="cpguard-scan-{pk}.sarif"'
    return resp


def export_csv(request, pk: int):
    """표 형태 내보내기 — 보고서·엑셀 정리를 위한 실무 기능."""
    scan = get_object_or_404(Scan, pk=pk)
    audit = scan.audit
    resp = HttpResponse(content_type="text/csv; charset=utf-8-sig")
    resp["Content-Disposition"] = f'attachment; filename="cpguard-scan-{pk}.csv"'
    resp.write("﻿")  # 엑셀 한글 깨짐 방지
    w = csv.writer(resp)
    w.writerow(["번호", "위험도", "규칙", "CWE", "OWASP", "파일", "라인",
                "설명", "LLM판정", "감사상태", "흐름단계수"])
    for f in scan.findings:
        w.writerow([f["id"], f["severity"], f["rule_id"], f["cwe"], f.get("owasp", ""),
                    f["file"], f["line"], f["message"], f.get("verdict") or "",
                    audit.get(str(f["id"]), ""), len(f["steps"])])
    return resp


def _findings_from_scan(scan: Scan) -> list[Finding]:
    """저장된 JSON 을 Finding 객체로 되살린다 (엑셀 리포터가 Finding 을 받는다)."""
    from ..ir import Loc
    from ..report.finding import Step
    out: list[Finding] = []
    for d in scan.findings:
        steps = [
            Step(s["kind"], Loc(file=s["file"], start_line=s["line"], start_col=0,
                                end_line=s["line"], end_col=0, start_byte=0, end_byte=0),
                 s["code"])
            for s in d.get("steps", [])
        ] or [Step("match", Loc(file=d["file"], start_line=d["line"], start_col=0,
                                end_line=d["line"], end_col=0, start_byte=0, end_byte=0), "")]
        out.append(Finding(
            rule_id=d["rule_id"], message=d["message"], severity=d["severity"],
            cwe=d.get("cwe", ""), owasp=d.get("owasp", ""), steps=steps,
            verdict=d.get("verdict"), confidence=d.get("confidence"),
            triage_reason=d.get("triage_reason"), triage_provider=d.get("triage_provider"),
            precision=d.get("precision", "high"), fp_hint=bool(d.get("fp_hint", False)),
            matched_value=d.get("matched_value"), category=d.get("category", "flow"),
        ))
    return out


def export_xlsx(request, pk: int):
    """고객 제출용 분석목록표 — 조치여부/조치방법 컬럼과 표준 이슈 의견이 들어간다."""
    from ..report import excel
    scan = get_object_or_404(Scan, pk=pk)
    findings = _findings_from_scan(scan)
    tmp = Path(tempfile.mkdtemp(prefix="cpguard_xlsx_")) / "out.xlsx"
    try:
        excel.write_workbook(findings, tmp, project=Path(scan.name).stem, audit=scan.audit)
        data = tmp.read_bytes()
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)
    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = (
        f'attachment; filename="{Path(scan.name).stem}_소스코드_취약점진단_분석목록표.xlsx"')
    return resp


def delete(request, pk: int):
    if request.method == "POST":
        get_object_or_404(Scan, pk=pk).delete()
    return redirect("index")
