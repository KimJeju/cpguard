"""대시보드 뷰 — zip 업로드 → 안전해제 → 스캔 → 결과."""
from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from ..extract import UnsafeArchive, safe_extract_zip
from ..report.finding import Finding
from ..report.sarif import to_sarif
from ..scanner import scan_path
from .models import Scan


def _finding_to_dict(f: Finding, base: Path) -> dict:
    def rel(p: str) -> str:
        try:
            return str(Path(p).resolve().relative_to(base)).replace("\\", "/")
        except Exception:
            return Path(p).name

    return {
        "rule_id": f.rule_id,
        "message": f.message,
        "severity": f.severity,
        "cwe": f.cwe,
        "file": rel(f.sink.loc.file),
        "line": f.sink.loc.start_line,
        "steps": [
            {"kind": s.kind, "file": rel(s.loc.file), "line": s.loc.start_line, "code": s.code}
            for s in f.steps
        ],
    }


def index(request):
    return render(request, "index.html", {"scans": Scan.objects.all()[:30]})


def upload(request):
    if request.method != "POST":
        return redirect("index")

    up = request.FILES.get("archive")
    if not up:
        return render(request, "index.html",
                      {"scans": Scan.objects.all()[:30], "error": "zip 파일을 선택하세요."})
    if not up.name.lower().endswith(".zip"):
        return render(request, "index.html",
                      {"scans": Scan.objects.all()[:30], "error": "zip 파일만 지원합니다."})

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
                "scans": Scan.objects.all()[:30],
                "error": f"안전하지 않은 아카이브라 거부했습니다 — {e}",
            })

        findings, file_count = scan_path(src_dir)
        base = src_dir.resolve()
        scan = Scan.objects.create(
            name=up.name,
            file_count=file_count,
            finding_count=len(findings),
            findings_json=json.dumps([_finding_to_dict(f, base) for f in findings], ensure_ascii=False),
            sarif_json=json.dumps(to_sarif(findings, base), ensure_ascii=False),
        )
        return redirect("detail", pk=scan.pk)
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


def detail(request, pk: int):
    scan = get_object_or_404(Scan, pk=pk)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = sorted(scan.findings, key=lambda f: order.get(f["severity"], 9))
    return render(request, "detail.html", {"scan": scan, "findings": findings})


def sarif_download(request, pk: int):
    scan = get_object_or_404(Scan, pk=pk)
    resp = HttpResponse(scan.sarif_json, content_type="application/json")
    resp["Content-Disposition"] = f'attachment; filename="cpguard-scan-{pk}.sarif"'
    return resp


def delete(request, pk: int):
    if request.method == "POST":
        get_object_or_404(Scan, pk=pk).delete()
    return redirect("index")
