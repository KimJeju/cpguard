"""독립 데스크톱 창.

브라우저 탭이 아니라 자체 창으로 뜬다. 내부적으로는 로컬 Django 서버를 띄우고
OS 내장 웹뷰(Windows: WebView2/EdgeHTML)를 감싼 네이티브 창에 붙인다.
설치형 배포(install.exe)에서 실행 파일을 더블클릭하면 이 경로로 들어온다.

서버는 127.0.0.1 에만 바인딩하고 사용하지 않는 포트를 골라 쓴다.
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
import webbrowser
from pathlib import Path

TITLE = "CPGuard"
WIDTH, HEIGHT = 1280, 860
STARTUP_TIMEOUT = 25.0


class DesktopUnavailable(RuntimeError):
    """pywebview 미설치 등으로 데스크톱 창을 띄울 수 없음."""


class _WinApi:
    """프레임리스 창의 커스텀 상단바가 부르는 창 제어 API.

    JS 에서 window.pywebview.api.minimize() 처럼 호출한다. OS 제목표시줄을 없앤 대신
    앱 헤더에 최소화/최대화/닫기 버튼을 두고 여기로 연결한다.
    """

    def __init__(self) -> None:
        # 밑줄 접두: pywebview 가 js_api 를 JS 로 노출할 때 이 속성을 훑지 않게 한다.
        # 공개 속성으로 pywebview Window 를 들면 브리지가 .native 를 재귀 직렬화하다 죽는다.
        self._window = None
        self._maximized = False

    def _set_window(self, window) -> None:
        self._window = window

    def minimize(self) -> None:
        if self._window:
            self._window.minimize()

    def toggle_maximize(self) -> None:
        if not self._window:
            return
        if self._maximized:
            self._window.restore()
        else:
            self._window.maximize()
        self._maximized = not self._maximized

    def close(self) -> None:
        if self._window:
            self._window.destroy()


def _ensure_std_streams() -> None:
    """windowed(console=False) frozen 앱에선 sys.stdout/stderr 가 None 이다.
    Django runserver 는 시작 배너를 verbosity 와 무관하게 self.stdout 에 쓰므로,
    스트림이 None 이면 배너를 쓰다 죽어 서버가 포트를 못 연다(창도 안 뜬다).
    None 이면 로그 파일로 돌려 크래시를 막고 진단 로그도 남긴다."""
    if sys.stdout is not None and sys.stderr is not None:
        return
    data = Path(os.environ.get("CPGUARD_HOME", Path.home() / ".cpguard"))
    try:
        data.mkdir(parents=True, exist_ok=True)
        fh = open(data / "desktop.log", "a", encoding="utf-8", buffering=1)
    except Exception:
        fh = open(os.devnull, "w", encoding="utf-8")
    if sys.stdout is None:
        sys.stdout = fh
    if sys.stderr is None:
        sys.stderr = fh


def free_port() -> int:
    """사용 가능한 포트를 OS 에서 받아온다."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_up(url: str, timeout: float = STARTUP_TIMEOUT) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1):
                return True
        except urllib.error.HTTPError:
            return True          # 응답이 왔으면 서버는 살아있다
        except Exception:
            time.sleep(0.2)
    return False


def _serve(host: str, port: int) -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cpguard.web.settings")
    import django
    django.setup()
    from django.core.management import call_command

    # 절대 import — frozen 앱에선 desktop.py 가 __main__ 이라 상대 import(.web...)가 깨진다
    from cpguard.web.config import apply_to_env  # 저장된 LLM 키를 환경변수로
    apply_to_env()
    call_command("migrate", verbosity=0, interactive=False)
    call_command("runserver", f"{host}:{port}", use_reloader=False, verbosity=0)


def _run_in_browser(url: str, server: threading.Thread, reason: str) -> None:
    """네이티브 창을 못 띄울 때의 폴백 — 기본 브라우저로 열고 서버를 살려둔다.

    클린/에어갭 머신엔 WebView2 런타임이 없을 수 있다. 그런 곳에서도 최소한
    브라우저로는 동작해야 하므로, 창 생성 실패를 치명적 오류로 보지 않는다.
    데몬 서버 스레드에 메인을 붙잡아 두어(join) 프로세스가 살아있게 한다.
    """
    print(f"[네이티브 창 대신 브라우저로 엽니다] {reason}")
    print(f"CPGuard: {url}   (종료: Ctrl+C)")
    try:
        webbrowser.open(url)
    except Exception:
        pass
    try:
        server.join()
    except KeyboardInterrupt:
        pass


def launch(port: int | None = None, debug: bool = False) -> None:
    """로컬 서버를 띄우고 네이티브 창으로 대시보드를 연다.

    WebView2 런타임 부재 등으로 창을 못 띄우면 기본 브라우저로 폴백한다
    (클린 머신 배포 대비).
    """
    _ensure_std_streams()
    host = "127.0.0.1"
    port = port or free_port()
    url = f"http://{host}:{port}/"

    # 서버는 데몬 스레드로 — 창을 닫으면 프로세스와 함께 정리된다
    server = threading.Thread(target=_serve, args=(host, port), daemon=True)
    server.start()

    if not _wait_until_up(url):
        raise DesktopUnavailable(f"로컬 서버가 시간 내에 뜨지 않았습니다: {url}")

    # 1순위: 네이티브 창(pywebview). 미탑재/런타임부재면 브라우저로 폴백.
    try:
        import webview
    except ImportError as e:
        return _run_in_browser(url, server, reason=f"웹뷰 미탑재: {e!r}")
    try:
        api = _WinApi()
        # frameless: OS 제목표시줄 제거. 대신 앱 헤더가 드래그 영역·창버튼을 제공한다.
        window = webview.create_window(TITLE, url, js_api=api, frameless=True,
                                       width=WIDTH, height=HEIGHT,
                                       min_size=(900, 600), confirm_close=False)
        api._set_window(window)
        webview.start(debug=debug)
    except Exception as e:  # WebView2 런타임 부재 등 — 창 대신 브라우저로
        return _run_in_browser(url, server, reason=f"네이티브 창 실패: {e!r}")


def main() -> int:
    try:
        launch()
    except DesktopUnavailable as e:
        print(f"[데스크톱 창 실패] {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
