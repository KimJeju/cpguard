"""비동기 스캔 작업 — 리포 전체 감사는 분 단위라 도구 호출을 막지 않는다.

`scan_start` 가 백그라운드 스레드로 scan_path 를 돌리고 job_id 를 즉시 돌려준다.
`scan_status` 는 숫자만(진행률·건수) 반환한다 — findings 를 통째로 붓지 않는다.
끝나면 findings 를 공유 FindingStore 에 등록해 finding.list·evidence·probe 가
이어받는다.

멀티프로세스가 아니라 스레드다: 결과를 피클할 필요가 없고 같은 FindingStore 를
그대로 쓴다. taint 는 GIL-bound 라 병렬 가속은 없지만, 목적은 '가속'이 아니라
'도구 호출을 막지 않기'다. scan_path 자체의 jobs= 병렬은 프로세스풀이라 별개.
"""
from __future__ import annotations

import threading
import time
import uuid
from pathlib import Path

from .tools import FindingStore


class JobRunner:
    """스캔 작업들을 들고 있는다. 서버 프로세스 한 대화 분량(영속 아님)."""

    def __init__(self, store: FindingStore) -> None:
        self._store = store
        self._jobs: dict[str, dict] = {}
        self._lock = threading.Lock()

    def start(self, root: str, jobs: int = 1) -> dict:
        p = Path(root)
        if not p.exists():
            return {"error": "not_found", "path": str(p)}

        job_id = "scan_" + uuid.uuid4().hex[:12]
        with self._lock:
            self._jobs[job_id] = {
                "status": "queued", "root": str(p), "phase": None,
                "done": 0, "total": 0, "found": 0, "counts": {},
                "error": None, "started": time.time(), "finished": None,
            }
        t = threading.Thread(target=self._run, args=(job_id, p, jobs), daemon=True)
        t.start()
        return {"job_id": job_id, "status": "queued", "root": str(p)}

    def _progress(self, job_id: str):
        def cb(phase, done, total, found):
            with self._lock:
                j = self._jobs[job_id]
                j.update(status="running", phase=phase, done=done, total=total, found=found)
        return cb

    def _run(self, job_id: str, root: Path, jobs: int) -> None:
        from cpguard.scanner import scan_path
        try:
            findings, _report = scan_path(root, progress=self._progress(job_id), jobs=jobs)
            registered = self._store.register(findings)   # FindingStore 가 자체 락을 갖진 않지만
            counts: dict[str, int] = {}                    # 등록은 이 스레드에서 한 번뿐이라 경합 없음
            for _fid, f in registered:
                counts[f.severity] = counts.get(f.severity, 0) + 1
            with self._lock:
                self._jobs[job_id].update(status="completed", phase="done",
                                          found=len(registered), counts=counts,
                                          finished=time.time())
        except Exception as e:                             # 스캔 실패를 조용히 삼키지 않는다
            with self._lock:
                self._jobs[job_id].update(status="failed", error=f"{type(e).__name__}: {e}",
                                          finished=time.time())

    def status(self, job_id: str) -> dict:
        """숫자만 — findings 는 finding.list 로 가져간다(토큰 예산)."""
        with self._lock:
            j = self._jobs.get(job_id)
            if j is None:
                return {"error": "unknown_job", "job_id": job_id}
            out = {"job_id": job_id, "status": j["status"], "root": j["root"],
                   "phase": j["phase"], "done": j["done"], "total": j["total"],
                   "found": j["found"]}
            if j["status"] == "completed":
                out["counts"] = j["counts"]
                out["note"] = "finding.list 로 결과를 가져간다(필터·페이지)."
            if j["error"]:
                out["error"] = j["error"]
            return out
