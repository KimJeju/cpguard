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


def test_frameless_window_disables_easy_drag(monkeypatch):
    """easy_drag 기본값(True)이면 창 어디를 눌러 끌든 창이 따라 움직인다.

    pywebview 의 easy_drag 는 window 전체에 mousedown 을 걸고 대상을 가리지 않는다.
    그래서 패널 크기 조절 거터를 끄는 순간 창이 움직이고, 최대화 상태면 그대로 풀린다 —
    AI 패널·좌측 탐색기 폭 조절이 사실상 불가능해진다. 헤더(.pywebview-drag-region)만
    드래그 영역으로 남기려면 반드시 꺼야 한다.
    """
    captured = {}

    class _FakeWindow:
        events = type("E", (), {"closed": type("C", (), {"__iadd__": lambda s, f: s})()})()

    class _FakeWebview:
        settings: dict = {}

        @staticmethod
        def create_window(*a, **kw):
            captured.update(kw)
            return _FakeWindow()

        @staticmethod
        def start(**kw):
            pass

    monkeypatch.setitem(sys.modules, "webview", _FakeWebview)
    monkeypatch.setattr(desktop, "_wait_until_up", lambda url, **kw: True)
    monkeypatch.setattr(desktop.threading, "Thread", lambda **kw: type(
        "T", (), {"start": lambda s: None, "join": lambda s, *a: None, "daemon": True})())

    desktop.launch(port=9)
    assert captured.get("frameless") is True
    assert captured.get("easy_drag") is False, "easy_drag 가 켜지면 거터 드래그가 창을 움직인다"
