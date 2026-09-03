"""데스크톱 런처 — WebView2 없는 클린 머신용 브라우저 폴백."""
from __future__ import annotations

import threading

from cpguard import desktop


def test_run_in_browser_opens_url_and_returns_when_server_ends(monkeypatch):
    opened: list[str] = []
    monkeypatch.setattr(desktop.webbrowser, "open", lambda u: opened.append(u))
    # 즉시 끝나는 더미 서버 스레드 — join 이 바로 반환되어 폴백이 종료된다
    server = threading.Thread(target=lambda: None)
    server.start()
    desktop._run_in_browser("http://127.0.0.1:9/", server, reason="test")
    assert opened == ["http://127.0.0.1:9/"]
