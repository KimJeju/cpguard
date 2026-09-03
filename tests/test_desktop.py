"""데스크톱 런처 — WebView2 없는 클린 머신용 브라우저 폴백."""
from __future__ import annotations

import sys
import threading

from cpguard import desktop


def test_ensure_std_streams_redirects_when_none(tmp_path, monkeypatch):
    # windowed frozen 앱 재현: stdout/stderr 가 None 이면 로그 파일로 돌려 크래시를 막는다.
    monkeypatch.setenv("CPGUARD_HOME", str(tmp_path))
    real_out, real_err = sys.stdout, sys.stderr
    try:
        sys.stdout = None
        sys.stderr = None
        desktop._ensure_std_streams()
        assert sys.stdout is not None and sys.stderr is not None
        print("does not crash")  # None 이었다면 여기서 죽었을 것
    finally:
        opened = sys.stdout
        sys.stdout, sys.stderr = real_out, real_err
        try:
            opened.close()
        except Exception:
            pass
    assert (tmp_path / "desktop.log").exists()


def test_run_in_browser_opens_url_and_returns_when_server_ends(monkeypatch):
    opened: list[str] = []
    monkeypatch.setattr(desktop.webbrowser, "open", lambda u: opened.append(u))
    # 즉시 끝나는 더미 서버 스레드 — join 이 바로 반환되어 폴백이 종료된다
    server = threading.Thread(target=lambda: None)
    server.start()
    desktop._run_in_browser("http://127.0.0.1:9/", server, reason="test")
    assert opened == ["http://127.0.0.1:9/"]
