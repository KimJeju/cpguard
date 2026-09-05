"""대시보드 뷰 — zip 업로드 → 안전해제 → 스캔 → 감사 작업대."""
from __future__ import annotations

import csv
import json
import os
import queue
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path

from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST

from ..extract import UnsafeArchive, safe_extract_zip
from ..i18n import tr
from ..report.finding import Finding
from ..report.sarif import to_sarif
from ..scanner import scan_path
from .models import Scan


def _lang(request) -> str:
    """응답 언어 — 헤더 토글이 심는 쿠키(cpguard_lang)/`?lang=` 로 판별. 기본 ko.

    UI 는 클라이언트 사전으로 번역하지만 룰 메시지·PDF 는 서버 생성이라 여기서 고른다."""
    return "en" if (request.GET.get("lang") or request.COOKIES.get("cpguard_lang")) == "en" else "ko"

# 코드 뷰어용 원본 보관 한도 (DB 비대화 방지)
# 원본 보관 상한 — 대형 프로젝트(수천 파일에 탐지)에서도 뷰어가 원본을 보여줄 수 있게
# 넉넉히. 파일당 1MB, 총 64MB. 대량 모드에서는 페이지에 임베드하지 않고 이슈 선택 시
# 지연 로드(scan_finding_api)하므로 큰 총량도 감당한다.
MAX_SOURCE_BYTES = int(os.environ.get("CPGUARD_MAX_SOURCE_BYTES", str(1_000_000)))
MAX_SOURCES_TOTAL = int(os.environ.get("CPGUARD_MAX_SOURCES_TOTAL", str(64_000_000)))

AUDIT_STATES = ("", "confirmed", "false_positive", "fixed", "deferred")

# ---- 스캔 진행 상태 (백그라운드 스레드 → 진행바 폴링) ----
# 로컬 단일 프로세스 데스크톱 앱이라 메모리 dict 로 충분하다.
# ponytail: 전역 dict + 락. 다중 워커로 가면 캐시/DB 로 옮겨야 한다.
_JOBS: dict[str, dict] = {}
_JOBS_LOCK = threading.Lock()
_JOB_TTL = 3600  # 완료된 잡을 이 시간(초) 뒤 정리


def _job_set(job_id: str, **kw) -> None:
    with _JOBS_LOCK:
        _JOBS.setdefault(job_id, {}).update(kw)


def _job_get(job_id: str) -> dict:
    with _JOBS_LOCK:
        return dict(_JOBS.get(job_id, {}))


def _job_log(job_id: str, msg: str) -> None:
    """구동 상태 로그 한 줄 추가(시각 붙임). 최근 200줄만 유지."""
    line = time.strftime("%H:%M:%S") + "  " + msg
    with _JOBS_LOCK:
        log = _JOBS.setdefault(job_id, {}).setdefault("log", [])
        log.append(line)
        if len(log) > 200:
            del log[: len(log) - 200]


def _async_scan() -> bool:
    """스캔을 백그라운드 스레드로 돌릴지. 실서비스는 True(진행바 위해).
    pytest 중에는 스레드+테스트DB 트랜잭션이 안 맞으므로 동기로 돌린다.
    CPGUARD_SCAN_ASYNC=0 으로 강제 동기도 가능."""
    if os.environ.get("PYTEST_CURRENT_TEST"):
        return False
    return os.environ.get("CPGUARD_SCAN_ASYNC", "1") != "0"


# ---- 배치: 다건 프로젝트를 순차 처리하는 단일 워커 큐 ----
# 담당자가 수백 프로젝트를 한 번에 올릴 때, 프로젝트마다 스레드를 띄우면 스캐너 내부
# 멀티프로세싱과 CPU 가 과구독된다. 전역 FIFO 큐 + 워커 1개로 순차 처리한다.
# ponytail: 인메모리 큐 + 워커 1. 다중 워커/영속 큐가 필요하면 DB·Celery 로.
_QUEUE: "queue.Queue" = queue.Queue()
_BATCHES: dict[str, dict] = {}
_WORKER_STARTED = False
_WORKER_LOCK = threading.Lock()


def _batch_set(batch_id: str, **kw) -> None:
    with _JOBS_LOCK:
        _BATCHES.setdefault(batch_id, {}).update(kw)


def _batch_get(batch_id: str) -> dict:
    with _JOBS_LOCK:
        return dict(_BATCHES.get(batch_id, {}))


def _ensure_worker() -> None:
    """큐 워커 스레드 1개를 lazy 하게 띄운다."""
    global _WORKER_STARTED
    with _WORKER_LOCK:
        if _WORKER_STARTED:
            return
        _WORKER_STARTED = True
        threading.Thread(target=_worker_loop, name="cpguard-scan-worker", daemon=True).start()


def _worker_loop() -> None:
    while True:
        args = _QUEUE.get()
        try:
            _run_scan_job(*args)
        except Exception:  # 워커는 죽지 않는다 — 개별 잡 오류는 _run_scan_job 이 기록
            pass
        finally:
            _QUEUE.task_done()


def _enqueue_scan(args: tuple) -> None:
    _ensure_worker()
    _QUEUE.put(args)


def _split_batch_zip(zip_path: Path) -> list[tuple[str, Path]] | None:
    """'zip 안에 프로젝트 zip 여러 개'(배치 zip)면 각 내부 zip 을 개별 프로젝트로 펼친다.

    내부 .zip 멤버가 하나도 없으면 None(= 단일 프로젝트로 취급). 있으면 각 내부 zip 을
    자체 workdir/upload.zip 으로 풀어 (이름, workdir) 목록을 돌려준다.
    """
    try:
        with zipfile.ZipFile(zip_path) as zf:
            inner = [n for n in zf.namelist()
                     if n.lower().endswith(".zip") and not n.endswith("/")]
            if not inner:
                return None
            out: list[tuple[str, Path]] = []
            for name in inner[:2000]:               # 폭주 방지 상한
                wd = Path(tempfile.mkdtemp(prefix="cpguard_"))
                with zf.open(name) as src, open(wd / "upload.zip", "wb") as dst:
                    shutil.copyfileobj(src, dst)
                out.append((Path(name).name, wd))
            return out
    except zipfile.BadZipFile:
        return None


def _job_prune() -> None:
    now = time.time()
    with _JOBS_LOCK:
        for jid in [j for j, v in _JOBS.items()
                    if v.get("status") in ("done", "error") and now - v.get("ended", now) > _JOB_TTL]:
            _JOBS.pop(jid, None)


def _run_scan_job(job_id: str, workdir: Path, zip_name: str,
                  do_triage: bool, provider: str, secrets_only: bool = False,
                  model: str = "") -> None:
    """백그라운드 스캔 — 압축 해제 → 진행 콜백과 함께 스캔 → Scan 레코드 생성.

    secrets_only 면 데이터 흐름 축을 건너뛰고 패턴(시크릿·개인정보·설정)만 돈다.
    요청 스레드가 아니라 여기서 workdir 수명을 책임진다(완료 후 정리).
    """
    from django.db import connection
    # 진단 상태 화면의 단계 체크리스트 순서(트리아지는 켰을 때만)
    if secrets_only:
        steps = ["extract", "pattern", "save"]
    else:
        steps = ["extract", "parse", "dataflow"] + (["triage"] if do_triage else []) + ["pattern", "save"]
    _job_set(job_id, steps=steps)
    _job_log(job_id, f"업로드 수신: {zip_name}")
    try:
        src_dir = workdir / "src"
        _job_set(job_id, status="running", phase="extract", done=0, total=0, findings=0)
        _job_log(job_id, "압축 해제 중…")
        try:
            n = safe_extract_zip(workdir / "upload.zip", src_dir)
        except UnsafeArchive as e:
            _job_log(job_id, f"거부: 안전하지 않은 아카이브 — {e}")
            _job_set(job_id, status="error", error=f"안전하지 않은 아카이브라 거부했습니다 — {e}", ended=time.time())
            return
        _job_log(job_id, f"압축 해제 완료 · {n}개 파일")
        base = src_dir.resolve()

        _pstate = {"last": None}

        def prog(phase, done, total, nf):
            if phase == "done":   # 스캐너 종료 신호 — 체크리스트는 save 단계로 이어간다
                return
            _job_set(job_id, status="running", phase=phase, done=done, total=total, findings=nf)
            if phase != _pstate["last"]:
                _pstate["last"] = phase
                start = {"parse": "소스 파싱 시작", "dataflow": "데이터 흐름 분석 시작",
                         "pattern": "패턴 검사 시작"}.get(phase)
                if start:
                    _job_log(job_id, start + (f" · 대상 {total}개" if total else ""))
            elif total and done and done % max(1, total // 4) == 0 and done != total:
                _job_log(job_id, f"  {phase} {done}/{total} …")

        if secrets_only:
            _job_log(job_id, "시크릿·개인정보·설정 패턴 점검 (데이터 흐름 축 생략)")
        jobs = int(os.environ.get("CPGUARD_JOBS", "1") or "1")
        findings, scan_report = scan_path(src_dir, progress=prog, secrets_only=secrets_only, jobs=jobs)
        integrity_note = "" if scan_report.complete else scan_report.summary()
        _job_log(job_id, f"스캔 계산 완료 · 탐지 {len(findings)}건")

        triage_note = ""
        if do_triage and findings:
            _job_set(job_id, status="running", phase="triage", done=0, total=0, findings=len(findings))
            _job_log(job_id, "LLM 트리아지 실행…")
            from ..triage import TriageUnavailable, available, triage_findings
            from . import config as appcfg
            avail = available()
            eff = (provider or None) or (avail[0] if avail else None)
            try:
                triage_findings(findings, provider=provider or None,
                                model=(model.strip() or appcfg.model_for(eff)))
                _job_log(job_id, "트리아지 완료")
            except TriageUnavailable as e:
                triage_note = f"LLM 트리아지를 건너뛰었습니다 — {e}"
                _job_log(job_id, f"트리아지 건너뜀 — {e}")

        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: (order.get(f.severity, 9), f.rule_id))

        _job_set(job_id, status="running", phase="save", findings=len(findings))
        _job_log(job_id, "결과 집계·저장 중…")
        project = _project_of(zip_name)
        from collections import Counter as _Counter
        sevc = _Counter(f.severity for f in findings)
        scan = Scan.objects.create(
            name=zip_name, project=project,
            file_count=scan_report.scanned, finding_count=len(findings),
            findings_json=json.dumps(
                [_finding_to_dict(i, f, base) for i, f in enumerate(findings)], ensure_ascii=False),
            sarif_json=json.dumps(to_sarif(findings, base), ensure_ascii=False),
            sources_json=json.dumps(_collect_sources(findings, base), ensure_ascii=False),
            triage_note=triage_note, integrity_note=integrity_note,
            sev_critical=sevc.get("critical", 0), sev_high=sevc.get("high", 0),
            sev_medium=sevc.get("medium", 0), sev_low=sevc.get("low", 0), sev_info=sevc.get("info", 0),
        )
        # 인덱스된 Finding 행 적재(서버측 필터·집계·페이지네이션용, 대량 탐지 대응)
        from .models import FindingRow
        FindingRow.objects.bulk_create([
            FindingRow(scan=scan, idx=d["id"], severity=d["severity"], rule_id=d["rule_id"],
                       cwe=d.get("cwe") or "", owasp=d.get("owasp") or "", file=d["file"], line=d["line"],
                       fp=d.get("fp") or "", category=d.get("category") or "",
                       verdict=d.get("verdict") or "", message=d.get("message") or "")
            for d in scan.findings], batch_size=1000)

        prev = scan.previous()
        if prev is not None:
            diff = scan.compare_with(prev)
            scan.new_count = len(diff["new"])
            scan.resolved_count = len(diff["resolved"])
            scan.save(update_fields=["new_count", "resolved_count"])

        _job_log(job_id, f"저장 완료 · 스캔 #{scan.pk} · 진단 종료")
        _job_set(job_id, status="done", pk=scan.pk, findings=len(findings), ended=time.time())
    except Exception as e:  # 스캔 중 예외 — 진행 페이지에 그대로 보여준다
        _job_log(job_id, f"오류: {type(e).__name__}: {e}")
        _job_set(job_id, status="error", error=f"{type(e).__name__}: {e}", ended=time.time())
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
        # 백그라운드 스레드일 때만 커넥션 정리 — 동기(테스트) 실행에선 요청 커넥션을 닫으면 안 된다
        if threading.current_thread() is not threading.main_thread():
            connection.close()


def _base_context() -> dict:
    from ..triage import available
    scans = list(Scan.objects.all()[:60])
    # 프로젝트별 최신 스캔만 — 홈 목록은 프로젝트 단위로 보여준다
    latest: dict[str, Scan] = {}
    for s in scans:
        key = s.project or s.name
        if key not in latest:
            latest[key] = s

    # ---- 대시보드 집계 (프로젝트별 최신 스캔 기준) ----
    # 위험도는 비정규화 컬럼에서, 상위 규칙은 FindingRow GROUP BY 에서 — findings_json
    # 역직렬화 없이. 수백 프로젝트에서도 조회가 가볍다.
    sev_keys = ["critical", "high", "medium", "low", "info"]
    agg = {k: 0 for k in sev_keys}
    total = 0
    new_total = 0
    for s in latest.values():
        for k, v in s.sev_counts_fast.items():
            agg[k] = agg.get(k, 0) + v
        total += s.finding_count
        new_total += s.new_count
    from django.db.models import Count
    from .models import FindingRow
    latest_ids = [s.id for s in latest.values()]
    rule_agg = {r["rule_id"]: r["n"] for r in
                FindingRow.objects.filter(scan_id__in=latest_ids)
                .values("rule_id").annotate(n=Count("id")).order_by("-n")[:8]}
    stats = {
        "total": total,
        "sev": agg,
        "sev_max": max(agg.values()) or 1,
        "crit_high": agg["critical"] + agg["high"],
        "projects": len(latest),
        "scans": len(scans),
        "new_total": new_total,
        "top_rules": sorted(rule_agg.items(), key=lambda x: -x[1])[:8],
        "top_rules_max": max(rule_agg.values()) if rule_agg else 1,
    }
    sev_labels = [("critical", "심각 Critical"), ("high", "높음 High"),
                  ("medium", "중간 Medium"), ("low", "낮음 Low"), ("info", "정보 Info")]
    sev_rows = [{"key": k, "label": lb, "n": agg[k]} for k, lb in sev_labels]
    return {"scans": scans[:30], "projects": list(latest.values()),
            "providers": available(), "stats": stats, "sev_rows": sev_rows}


def settings_page(request):
    """LLM API 키 설정 — DATA_DIR/config.json 에 저장하고 환경변수로 적용."""
    from . import config as appcfg
    from ..triage import available
    if request.method == "POST":
        cfg = appcfg.load()
        mdls = dict(cfg.get("models") or {})
        for _cid, env, _label, pname in appcfg.KEYS:
            if request.POST.get(f"clear_{env}"):
                cfg.pop(env, None)
                os.environ.pop(env, None)
            else:
                v = (request.POST.get(env) or "").strip()
                if v and "•" not in v:   # 마스킹된 표시값 그대로면 변경 안 함
                    cfg[env] = v
                    os.environ[env] = v   # 재시작 없이 즉시 적용
            # 모델 오버라이드 (빈 값이면 프로바이더 기본으로 되돌림)
            m = (request.POST.get(f"model_{pname}") or "").strip()
            if m:
                mdls[pname] = m
            else:
                mdls.pop(pname, None)
        for _cid, env, _label in appcfg.EXTRA_ENV:
            if request.POST.get(f"clear_{env}"):
                cfg.pop(env, None)
                os.environ.pop(env, None)
            else:
                v = (request.POST.get(env) or "").strip()
                if v and "•" not in v:
                    cfg[env] = v
                    os.environ[env] = v
        cfg["models"] = mdls
        # 보고서 메타(작성자·기관·발주처·담당자·기간·버전) — PDF 표지/개정이력용
        cfg["report"] = {k: (request.POST.get(f"report_{k}") or "").strip()
                         for k, _l, _p in appcfg.REPORT_FIELDS}
        appcfg.save(cfg)
        return redirect("settings")

    from ..triage.providers import PROVIDERS
    defaults = {name: cls.default_model for name, cls in PROVIDERS.items()}
    cfg = appcfg.load()
    mdls = cfg.get("models") or {}
    rep = cfg.get("report") or {}
    report_fields = [{"key": k, "label": l, "placeholder": p, "value": rep.get(k, "")}
                     for k, l, p in appcfg.REPORT_FIELDS]
    rows = []
    for _cid, env, label, pname in appcfg.KEYS:
        stored = cfg.get(env) or os.environ.get(env, "")
        rows.append({"env": env, "label": label, "pname": pname,
                     "masked": appcfg.mask_key(stored) if stored else "",
                     "set": bool(stored),
                     "model": mdls.get(pname, ""),
                     "model_options": appcfg.MODEL_OPTIONS.get(pname, []),
                     "model_default": defaults.get(pname, "")})
    extras = []
    for _cid, env, label in appcfg.EXTRA_ENV:
        stored = cfg.get(env) or os.environ.get(env, "")
        extras.append({"env": env, "label": label,
                       "value": stored, "set": bool(stored)})
    return render(request, "settings.html",
                  {"rows": rows, "extras": extras, "providers": available(),
                   "report_fields": report_fields})


def compare(request):
    """스냅샷 비교 — 두 스캔을 골라 신규/해결/유지를 지문 기준으로 대조한다."""
    projects = sorted({p for p in Scan.objects.values_list("project", flat=True) if p})
    proj = request.GET.get("p") or ""
    qs = Scan.objects.filter(project=proj) if proj else Scan.objects.all()
    scans = list(qs[:80])
    a, b = request.GET.get("a"), request.GET.get("b")
    ctx: dict = {"scans": scans, "projects": projects, "proj": proj}
    if a and b:
        try:
            sa = Scan.objects.get(pk=int(a))
            sb = Scan.objects.get(pk=int(b))
        except (Scan.DoesNotExist, ValueError):
            return redirect("compare")
        diff = sb.compare_with(sa)   # sb(대상) 이 sa(기준) 대비
        ctx.update({"a": sa, "b": sb, "new": diff["new"],
                    "resolved": diff["resolved"], "persistent": diff["persistent"]})
    return render(request, "compare.html", ctx)


def reports(request):
    """리포트 — 스캔별 내보내기(SARIF/CSV/분석목록표/PDF) 바로가기."""
    return render(request, "reports.html", {"scans": list(Scan.objects.all()[:100])})


# 무거운 JSON 컬럼 — 포트폴리오 목록엔 필요 없으니 defer 로 로드 안 한다(수백 프로젝트 대응)
_HEAVY_COLS = ("findings_json", "sarif_json", "sources_json", "audit_json", "audit_notes_json")
_SORTS = {
    "recent": "-created_at", "oldest": "created_at",
    "name": "project", "findings": "-finding_count",
    "critical": "-sev_critical", "high": "-sev_high", "new": "-new_count",
}


def _latest_per_project():
    """프로젝트별 최신 스캔만. findings_json 등 무거운 컬럼은 로드하지 않는다."""
    latest: dict[str, Scan] = {}
    for s in Scan.objects.defer(*_HEAVY_COLS).order_by("-created_at").iterator():
        key = s.project or s.name
        if key not in latest:      # order_by -created_at → 첫 등장이 최신
            latest[key] = s
    return latest


def portfolio(request):
    """프로젝트 포트폴리오 — 담당자가 수백 프로젝트를 한눈에. 검색·정렬·필터·다중선택.

    위험도는 비정규화 컬럼에서 읽어 findings_json 역직렬화가 없다(대규모에서 즉답)."""
    rows = list(_latest_per_project().values())

    q = (request.GET.get("q") or "").strip().lower()
    if q:
        rows = [s for s in rows if q in (s.project or s.name).lower()]
    sev = request.GET.get("sev") or ""
    if sev in ("critical", "high", "medium", "low", "info"):
        rows = [s for s in rows if getattr(s, f"sev_{sev}", 0) > 0]

    sort = request.GET.get("sort", "critical")
    key = _SORTS.get(sort, "-sev_critical")
    reverse = key.startswith("-")
    field = key.lstrip("-")
    if field == "project":
        rows.sort(key=lambda s: (s.project or s.name).lower())
    else:
        rows.sort(key=lambda s: getattr(s, field, 0), reverse=reverse)
    # 위험도 정렬 시 2차 키로 high→medium→… 자연스럽게
    if field in ("sev_critical", "sev_high"):
        rows.sort(key=lambda s: (s.sev_critical, s.sev_high, s.sev_medium, s.finding_count), reverse=True)

    total_projects = len(rows)
    # 페이지네이션
    try:
        page = max(1, int(request.GET.get("page", 1)))
    except ValueError:
        page = 1
    size = 50
    pages = max(1, (total_projects + size - 1) // size)
    page = min(page, pages)
    page_rows = rows[(page - 1) * size: page * size]

    # 전체 집계(필터 적용 후) — 헤더 요약
    agg = {k: sum(getattr(s, f"sev_{k}") for s in rows) for k in
           ("critical", "high", "medium", "low", "info")}
    return render(request, "portfolio.html", {
        "rows": page_rows, "total_projects": total_projects, "agg": agg,
        "q": request.GET.get("q") or "", "sev": sev, "sort": sort,
        "page": page, "pages": pages,
        "page_ids": ",".join(str(s.pk) for s in page_rows),
        "all_ids": ",".join(str(s.pk) for s in rows),
    })


@never_cache
def portfolio_export(request):
    """선택한 프로젝트들의 산출물(PDF 보고서 + xlsx 분석목록표)을 프로젝트별 폴더로
    묶은 ZIP. 담당자가 배치로 골라 개발자에게 배부하는 용도."""
    import io
    from ..report import excel
    from ..report import pdf as pdfmod

    from . import config as appcfg
    lang = _lang(request)
    meta = appcfg.report_meta()
    ids = [int(x) for x in (request.GET.get("ids") or "").split(",") if x.strip().isdigit()]
    ids = ids[:300]                                  # 폭주 방지 상한
    kind = request.GET.get("kind", "both")           # report | xlsx | both
    scans = list(Scan.objects.filter(pk__in=ids))
    if not scans:
        return HttpResponse("선택된 프로젝트가 없습니다.", status=400)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for scan in scans:
            proj = (scan.project or Path(scan.name).stem)
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in proj)[:80] or f"scan{scan.pk}"
            folder = f"{safe}"
            if kind in ("report", "both"):
                tmp = Path(tempfile.mkdtemp(prefix="cpguard_pdf_")) / "r.pdf"
                try:
                    pdfmod.combined_report(scan, tmp, lang=lang, meta=meta)
                    zf.writestr(f"{folder}/{safe}_report.pdf", tmp.read_bytes())
                finally:
                    shutil.rmtree(tmp.parent, ignore_errors=True)
            if kind in ("xlsx", "both"):
                findings = _findings_from_scan(scan)
                tmp = Path(tempfile.mkdtemp(prefix="cpguard_xlsx_")) / "s.xlsx"
                try:
                    excel.write_workbook(findings, tmp, project=Path(scan.name).stem,
                                         audit=scan.audit, lang=lang)
                    zf.writestr(f"{folder}/{safe}_analysis-sheet.xlsx", tmp.read_bytes())
                finally:
                    shutil.rmtree(tmp.parent, ignore_errors=True)
    resp = HttpResponse(buf.getvalue(), content_type="application/zip")
    fname = "cpguard-deliverables.zip"
    resp["Content-Disposition"] = f'attachment; filename="{fname}"'
    return resp


def _pdf_response(scan, kind: str, lang: str = "ko"):
    from ..report import pdf as pdfmod
    from . import config as appcfg
    meta = appcfg.report_meta()          # 설정의 보고서 정보(작성자·기관·발주처·기간·버전)
    tmp = Path(tempfile.mkdtemp(prefix="cpguard_pdf_")) / "out.pdf"
    try:
        if kind == "guide":
            pdfmod.remediation_guide(scan, tmp, lang=lang, meta=meta)
            suffix = "remediation-guide" if lang == "en" else "조치가이드"
        else:
            pdfmod.combined_report(scan, tmp, lang=lang, meta=meta)
            suffix = "assessment-report" if lang == "en" else "진단결과보고서"
        data = tmp.read_bytes()
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)
    resp = HttpResponse(data, content_type="application/pdf")
    resp["Content-Disposition"] = f'attachment; filename="{Path(scan.name).stem}_{suffix}.pdf"'
    return resp


@never_cache
def export_pdf_report(request, pk: int):
    """합본 진단 결과 보고서(PDF)."""
    return _pdf_response(get_object_or_404(Scan, pk=pk), "combined", _lang(request))


@never_cache
def export_pdf_guide(request, pk: int):
    """유형별 조치 가이드(PDF)."""
    return _pdf_response(get_object_or_404(Scan, pk=pk), "guide", _lang(request))


# ---- 대량 탐지: 서버측 집계·페이지네이션 API (Finding 테이블 질의) ----

def scan_summary_api(request, pk: int):
    """스캔 집계(위험도·상위 규칙·상위 파일) — DB 집계라 5만 건도 즉답."""
    from django.db.models import Count
    from .models import FindingRow
    get_object_or_404(Scan, pk=pk)
    qs = FindingRow.objects.filter(scan_id=pk)
    sev = {r["severity"]: r["n"] for r in qs.values("severity").annotate(n=Count("id"))}
    rules = qs.values("rule_id").annotate(n=Count("id")).order_by("-n")[:15]
    files = qs.values("file").annotate(n=Count("id")).order_by("-n")[:15]
    cats = qs.exclude(category="").values("category").annotate(n=Count("id")).order_by("-n")
    cwes = qs.exclude(cwe="").values("cwe").annotate(n=Count("id")).order_by("-n")[:12]
    verdicts = qs.exclude(verdict="").values("verdict").annotate(n=Count("id")).order_by("-n")
    return JsonResponse({
        "total": qs.count(), "severity": sev,
        "top_rules": [[r["rule_id"], r["n"]] for r in rules],
        "top_files": [[r["file"], r["n"]] for r in files],
        "by_category": [[r["category"], r["n"]] for r in cats],
        "top_cwe": [[r["cwe"], r["n"]] for r in cwes],
        "by_verdict": [[r["verdict"], r["n"]] for r in verdicts],
    })


def scan_findings_api(request, pk: int):
    """필터·정렬·페이지네이션된 finding 목록(JSON). 작업대 가상 스크롤용."""
    from django.db.models import Case, IntegerField, Q, When
    from .models import FindingRow
    get_object_or_404(Scan, pk=pk)
    qs = FindingRow.objects.filter(scan_id=pk)

    if sev := request.GET.get("severity"):
        qs = qs.filter(severity=sev)
    if rule := request.GET.get("rule"):
        qs = qs.filter(rule_id=rule)
    if f := request.GET.get("file"):
        qs = qs.filter(file=f)
    if q := (request.GET.get("q") or "").strip():
        qs = qs.filter(Q(rule_id__icontains=q) | Q(file__icontains=q)
                       | Q(message__icontains=q) | Q(cwe__icontains=q))

    sev_rank = Case(When(severity="critical", then=0), When(severity="high", then=1),
                    When(severity="medium", then=2), When(severity="low", then=3),
                    default=4, output_field=IntegerField())
    qs = qs.annotate(_sr=sev_rank).order_by("_sr", "rule_id", "file", "line")

    total = qs.count()
    try:
        page = max(1, int(request.GET.get("page", 1)))
        size = min(max(1, int(request.GET.get("size", 100))), 500)
    except ValueError:
        page, size = 1, 100
    rows = list(qs[(page - 1) * size: page * size].values(
        "idx", "severity", "rule_id", "cwe", "owasp", "file", "line", "fp", "category", "verdict"))
    return JsonResponse({"total": total, "page": page, "size": size, "rows": rows})


def scan_finding_api(request, pk: int, idx: int):
    """단일 finding 의 전체 상세(흐름 steps) + 그 이슈가 touch 하는 원본만 — 대량 모드에서
    선택 시 지연 로드용."""
    scan = get_object_or_404(Scan, pk=pk)
    findings = scan.findings
    if not (0 <= idx < len(findings)):
        return JsonResponse({"error": "없는 이슈"}, status=404)
    f = findings[idx]
    f["audit"] = scan.audit.get(str(idx), "")
    f["audit_note"] = scan.audit_notes.get(str(idx), "")
    f["message"] = tr(f.get("message", ""), _lang(request))
    prev = scan.previous()
    new_fps = scan.compare_with(prev)["new_fps"] if prev else set()
    f["is_new"] = bool(prev) and f.get("fp") in new_fps
    src = scan.sources
    want = {s["file"] for s in f.get("steps", [])}
    subset = {k: v for k, v in src.items()
              if k in want or any(k.endswith("/" + fn) or fn.endswith("/" + k) for fn in want)}
    return JsonResponse({"finding": f, "sources": subset})


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
    ctx = _base_context()
    ctx["secrets_mode"] = request.GET.get("mode") == "secrets"
    return render(request, "index.html", ctx)


def _render_markdown(md: str) -> str:
    """가이드용 최소 마크다운 → HTML. 외부 의존성 없이(오프라인) 필요한 문법만 지원:
    제목·목록(순서/비순서)·코드블록·인라인코드·굵게·링크·인용·구분선."""
    import html
    import re

    out: list[str] = []
    list_tag = None          # 'ul' | 'ol' | None
    in_code = False
    code_buf: list[str] = []

    def close_list():
        nonlocal list_tag
        if list_tag:
            out.append(f"</{list_tag}>")
            list_tag = None

    def inline(s: str) -> str:
        s = html.escape(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"\[([^\]]+)\]\(([^)]+)\)",
                   r'<a href="\2" target="_blank" rel="noopener">\1</a>', s)
        return s

    for ln in md.split("\n"):
        if ln.strip().startswith("```"):
            if in_code:
                out.append("<pre><code>" + html.escape("\n".join(code_buf)) + "</code></pre>")
                code_buf, in_code = [], False
            else:
                close_list(); in_code = True
            continue
        if in_code:
            code_buf.append(ln); continue
        if not ln.strip():
            close_list(); continue
        m = re.match(r"(#{1,4})\s+(.*)", ln)
        if m:
            close_list()
            lvl = len(m.group(1))
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>"); continue
        if ln.strip() == "---":
            close_list(); out.append("<hr>"); continue
        if ln.startswith("> "):
            close_list(); out.append(f"<blockquote>{inline(ln[2:])}</blockquote>"); continue
        m = re.match(r"\s*\d+\.\s+(.*)", ln)
        if m:
            if list_tag != "ol":
                close_list(); out.append("<ol>"); list_tag = "ol"
            out.append(f"<li>{inline(m.group(1))}</li>"); continue
        m = re.match(r"\s*[-*]\s+(.*)", ln)
        if m:
            if list_tag != "ul":
                close_list(); out.append("<ul>"); list_tag = "ul"
            out.append(f"<li>{inline(m.group(1))}</li>"); continue
        close_list()
        out.append(f"<p>{inline(ln)}</p>")
    close_list()
    if in_code and code_buf:
        out.append("<pre><code>" + html.escape("\n".join(code_buf)) + "</code></pre>")
    return "\n".join(out)


def guide(request):
    """사용 가이드 — 번들된 guide.md 를 렌더링."""
    from django.utils.safestring import mark_safe
    from pathlib import Path as _P
    md = (_P(__file__).parent / "guide.md").read_text(encoding="utf-8")
    return render(request, "guide.html", {"content": mark_safe(_render_markdown(md))})


def upload(request):
    """zip 을 하나 이상 받아 각 프로젝트를 workdir 에 저장하고 스캔을 큐에 넣는다.

    - 파일 여러 개(multi-select): 각 zip 이 프로젝트 하나.
    - zip 안에 프로젝트 zip 여러 개(배치 zip): 펼쳐서 각각 프로젝트.
    여러 프로젝트면 배치 진행 페이지로, 하나면 기존 단일 진행 페이지로 보낸다."""
    if request.method != "POST":
        return redirect("index")

    ups = request.FILES.getlist("archive")
    if not ups:
        return render(request, "index.html",
                      {**_base_context(), "error": "zip 파일을 선택하세요."})

    _job_prune()
    # (표시 이름, workdir) 목록으로 프로젝트를 모은다. 배치 zip 은 내부 zip 으로 펼친다.
    projects: list[tuple[str, Path]] = []
    skipped: list[str] = []
    for up in ups:
        if not up.name.lower().endswith(".zip"):
            skipped.append(up.name)
            continue
        wd = Path(tempfile.mkdtemp(prefix="cpguard_"))
        with open(wd / "upload.zip", "wb") as fh:
            for chunk in up.chunks():
                fh.write(chunk)
        inner = _split_batch_zip(wd / "upload.zip")
        if inner:
            projects.extend(inner)
            shutil.rmtree(wd, ignore_errors=True)   # 배치 컨테이너 자체는 스캔 안 함
        else:
            projects.append((up.name, wd))

    if not projects:
        msg = "zip 파일만 지원합니다." + (f" (건너뜀: {', '.join(skipped)})" if skipped else "")
        return render(request, "index.html", {**_base_context(), "error": msg})

    do_triage = bool(request.POST.get("triage"))
    provider = request.POST.get("provider", "")
    secrets_only = bool(request.POST.get("secrets_only"))
    model = request.POST.get("model", "")

    # 잡 생성
    jobs = []   # (job_id, args)
    for name, wd in projects:
        job_id = uuid.uuid4().hex
        args = (job_id, wd, name, do_triage, provider, secrets_only, model)
        jobs.append((job_id, args))

    async_ = _async_scan()

    # 단일 프로젝트 — 기존 단일 진행 흐름 유지(하위호환)
    if len(jobs) == 1:
        job_id, args = jobs[0]
        _job_set(job_id, status="running", phase="준비", done=0, total=0, findings=0,
                 name=args[2], started=time.time())
        if async_:
            _enqueue_scan(args)
            return redirect("scan_progress", job_id=job_id)
        _run_scan_job(*args)
        job = _job_get(job_id)
        if job.get("status") == "error":
            return render(request, "index.html", {**_base_context(), "error": job.get("error", "스캔 실패")})
        return redirect("detail", pk=job["pk"])

    # 다건 — 배치로 묶어 순차 처리
    batch_id = uuid.uuid4().hex
    job_ids = []
    for job_id, args in jobs:
        _job_set(job_id, status="queued", phase="대기", done=0, total=0, findings=0,
                 name=args[2], batch=batch_id)
        job_ids.append(job_id)
    _batch_set(batch_id, job_ids=job_ids, total=len(job_ids),
               started=time.time(), skipped=skipped)

    if async_:
        for _job_id, args in jobs:
            _enqueue_scan(args)
        return redirect("batch_progress", batch_id=batch_id)

    # 동기(테스트) — 순서대로 실행
    for _job_id, args in jobs:
        _run_scan_job(*args)
    return redirect("batch_progress", batch_id=batch_id)


def scan_progress(request, job_id: str):
    """스캔 진행 화면 — 상태를 폴링해 진행바를 갱신하고, 끝나면 작업대로 이동한다."""
    job = _job_get(job_id)
    if not job:
        return redirect("index")
    return render(request, "progress.html", {"job_id": job_id, "name": job.get("name", "")})


def scan_status(request, job_id: str):
    """진행 상태 JSON (진행 페이지가 폴링)."""
    job = _job_get(job_id)
    if not job:
        return JsonResponse({"status": "unknown"}, status=404)
    started = job.get("started")
    return JsonResponse({
        "status": job.get("status", "running"),
        "phase": job.get("phase", ""),
        "steps": job.get("steps", []),
        "done": job.get("done", 0),
        "total": job.get("total", 0),
        "findings": job.get("findings", 0),
        "pk": job.get("pk"),
        "error": job.get("error"),
        "elapsed": int(time.time() - started) if started else 0,
        "log": job.get("log", []),
    })


def batch_progress(request, batch_id: str):
    """배치 진행 화면 — 프로젝트별 상태 행 + 전체 진행. 다건 업로드용."""
    b = _batch_get(batch_id)
    if not b:
        return redirect("index")
    return render(request, "batch.html", {"batch_id": batch_id, "total": b.get("total", 0)})


def batch_status(request, batch_id: str):
    """배치 상태 JSON (배치 진행 페이지가 폴링)."""
    b = _batch_get(batch_id)
    if not b:
        return JsonResponse({"status": "unknown"}, status=404)
    jobs = []
    done = errored = 0
    for jid in b.get("job_ids", []):
        j = _job_get(jid)
        st = j.get("status", "queued")
        if st == "done":
            done += 1
        elif st == "error":
            errored += 1
        jobs.append({
            "name": j.get("name", ""), "status": st, "phase": j.get("phase", ""),
            "findings": j.get("findings", 0), "pk": j.get("pk"), "error": j.get("error"),
        })
    total = b.get("total", len(jobs))
    finished = done + errored
    return JsonResponse({
        "total": total, "done": done, "errored": errored, "finished": finished,
        "complete": finished >= total, "jobs": jobs,
        "started": b.get("started"),
        "elapsed": int(time.time() - b["started"]) if b.get("started") else 0,
    })


def detail(request, pk: int):
    """감사 작업대 — 좌: 이슈 트리, 중앙: 코드 뷰어, 우: 상세/흐름."""
    scan = get_object_or_404(Scan, pk=pk)
    lang = _lang(request)
    findings = scan.findings
    audit = scan.audit
    notes = scan.audit_notes
    for i, f in enumerate(findings):
        f.setdefault("id", i)   # 구버전/외부 생성 스캔은 id 가 없을 수 있다
        f["audit"] = audit.get(str(f["id"]), "")
        f["audit_note"] = notes.get(str(f["id"]), "")
        f["message"] = tr(f.get("message", ""), lang)

    # 이전 스캔 대비 신규 여부를 각 이슈에 표시 (조사 우선순위의 첫 번째 신호)
    prev = scan.previous()
    new_fps = scan.compare_with(prev)["new_fps"] if prev else set()
    for f in findings:
        f["is_new"] = bool(prev) and f.get("fp") in new_fps

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["file"], f["line"]))

    # 대량 탐지 가드: 5만 건을 통째로 브라우저에 임베드하면 멈춘다. 위험도 상위 N 만
    # 임베드하고 나머지는 집계 API(/api/summary, /api/findings)로 조회하도록 안내한다.
    total = len(findings)
    LARGE = 3000
    # ?large=1 로 소량 스캔에서도 대량 모드(서버측 목록)를 강제할 수 있다(데모·검증용).
    truncated = total if (total > LARGE or request.GET.get("large")) else 0
    if total > LARGE:
        findings = findings[:LARGE]

    # 대량 모드에서는 원본을 페이지에 임베드하지 않는다(64MB 를 통째로 넣으면 브라우저가 멈춘다).
    # 이슈를 고르면 scan_finding_api 가 그 이슈의 원본만 지연 로드한다.
    sources = {} if truncated else scan.sources

    return render(request, "workbench.html", {
        "scan": scan,
        "prev": prev,
        # 소스 원문에는 </script> 같은 문자열이 들어있을 수 있다.
        # 템플릿에서 json_script 필터로 내보내 스크립트 태그 탈출을 막는다.
        "findings": findings,
        "sources": sources,
        "counts": scan.severity_counts,
        "rule_counts": scan.rule_counts,
        "file_counts": scan.file_counts[:40],
        "total": total,
        "shown": len(findings),
        "truncated": truncated,
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
def set_audit_note(request, pk: int):
    """감사자 의견 메모 저장 — 평문으로만 저장하고 표시 시 escape 한다(HTML 렌더 안 함)."""
    scan = get_object_or_404(Scan, pk=pk)
    try:
        idx = int(request.POST.get("index", ""))
    except ValueError:
        return JsonResponse({"ok": False, "error": "잘못된 index"}, status=400)
    note = request.POST.get("note", "")
    scan.set_audit_note(idx, note)
    return JsonResponse({"ok": True, "index": idx, "note": scan.audit_notes.get(str(idx), "")})


@require_POST
def ai_ask(request, pk: int):
    """AI 분석 패널 — 현재 선택된 이슈의 맥락(규칙·흐름·주변 코드)을 자동으로 붙여 묻는다.

    키가 없으면 실패가 아니라 안내를 돌려준다(트리아지와 같은 원칙: 부가 기능).
    """
    from ..triage import PRESETS, TriageUnavailable, ask, available
    from . import config as appcfg
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
    prov = request.POST.get("provider") or None
    avail = available()
    eff_prov = prov or (avail[0] if avail else None)   # 자동일 때 실제 선택될 프로바이더
    try:
        answer, provider = ask(
            finding, scan.sources, preset=preset,
            question=request.POST.get("question") or None,
            provider=prov, model=appcfg.model_for(eff_prov),
        )
    except TriageUnavailable as e:
        return JsonResponse({"ok": False, "unavailable": True, "error": str(e)})
    except Exception as e:  # 프로바이더 오류는 패널에 그대로 보여준다
        return JsonResponse({"ok": False, "error": f"{type(e).__name__}: {e}"})
    return JsonResponse({"ok": True, "answer": answer, "provider": provider, "preset": preset})


@never_cache
def sarif_download(request, pk: int):
    scan = get_object_or_404(Scan, pk=pk)
    if _lang(request) == "en":
        # 저장된 sarif_json 은 KO 메시지라 EN 은 번역해 재생성한다(파일 경로는 이미 상대경로).
        findings = _findings_from_scan(scan)
        for f in findings:
            f.message = tr(f.message, "en")
        body = json.dumps(to_sarif(findings), indent=2, ensure_ascii=False)
    else:
        body = scan.sarif_json
    resp = HttpResponse(body, content_type="application/json")
    resp["Content-Disposition"] = f'attachment; filename="cpguard-scan-{pk}.sarif"'
    return resp


@never_cache
def export_csv(request, pk: int):
    """표 형태 내보내기 — 보고서·엑셀 정리를 위한 실무 기능."""
    scan = get_object_or_404(Scan, pk=pk)
    lang = _lang(request)
    audit = scan.audit
    resp = HttpResponse(content_type="text/csv; charset=utf-8-sig")
    resp["Content-Disposition"] = f'attachment; filename="cpguard-scan-{pk}.csv"'
    resp.write("﻿")  # 엑셀 한글 깨짐 방지
    w = csv.writer(resp)
    if lang == "en":
        w.writerow(["No", "Severity", "Rule", "CWE", "OWASP", "File", "Line",
                    "Description", "LLM verdict", "Audit", "Flow steps"])
    else:
        w.writerow(["번호", "위험도", "규칙", "CWE", "OWASP", "파일", "라인",
                    "설명", "LLM판정", "감사상태", "흐름단계수"])
    for f in scan.findings:
        w.writerow([f["id"], f["severity"], f["rule_id"], f["cwe"], f.get("owasp", ""),
                    f["file"], f["line"], tr(f["message"], lang), f.get("verdict") or "",
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


@never_cache
def export_xlsx(request, pk: int):
    """고객 제출용 분석목록표 — 조치여부/조치방법 컬럼과 표준 이슈 의견이 들어간다."""
    from ..report import excel
    scan = get_object_or_404(Scan, pk=pk)
    lang = _lang(request)
    findings = _findings_from_scan(scan)
    tmp = Path(tempfile.mkdtemp(prefix="cpguard_xlsx_")) / "out.xlsx"
    try:
        excel.write_workbook(findings, tmp, project=Path(scan.name).stem, audit=scan.audit, lang=lang)
        data = tmp.read_bytes()
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)
    stem = Path(scan.name).stem
    fname = f"{stem}_analysis-sheet.xlsx" if lang == "en" else f"{stem}_소스코드_취약점진단_분석목록표.xlsx"
    resp = HttpResponse(
        data, content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
    resp["Content-Disposition"] = f'attachment; filename="{fname}"'
    return resp


def delete(request, pk: int):
    if request.method == "POST":
        get_object_or_404(Scan, pk=pk).delete()
    return redirect("index")
