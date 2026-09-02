"""독립 데스크톱 창.

브라우저 탭이 아니라 자체 창으로 뜬다. 내부적으로는 로컬 Django 서버를 띄우고
OS 내장 웹뷰(Windows: WebView2/EdgeHTML)를 감싼 네이티브 창에 붙인다.
설치형 배포(install.exe)에서 실행 파일을 더블클릭하면 이 경로로 들어온다.

서버는 127.0.0.1 에만 바인딩하고 사용하지 않는 포트를 골라 쓴다.
"""
from __future__ import annotations

import os
import socket
import threading
import time
import urllib.error
import urllib.request

TITLE = "CPGuard — 정적 보안 분석"
WIDTH, HEIGHT = 1280, 860
STARTUP_TIMEOUT = 25.0


class DesktopUnavailable(RuntimeError):
    """pywebview 미설치 등으로 데스크톱 창을 띄울 수 없음."""


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

    call_command("migrate", verbosity=0, interactive=False)
    call_command("runserver", f"{host}:{port}", use_reloader=False, verbosity=0)


def launch(port: int | None = None, debug: bool = False) -> None:
    """로컬 서버를 띄우고 네이티브 창으로 대시보드를 연다."""
    try:
        import webview
    except ImportError as e:
        raise DesktopUnavailable(
            f"웹뷰를 불러오지 못했습니다: {e!r}. "
            "pip install pywebview 후 다시 시도하거나 'cpguard serve' 로 브라우저에서 여세요."
        ) from e

    host = "127.0.0.1"
    port = port or free_port()
    url = f"http://{host}:{port}/"

    # 서버는 데몬 스레드로 — 창을 닫으면 프로세스와 함께 정리된다
    threading.Thread(target=_serve, args=(host, port), daemon=True).start()

    if not _wait_until_up(url):
        raise DesktopUnavailable(f"로컬 서버가 시간 내에 뜨지 않았습니다: {url}")

    webview.create_window(TITLE, url, width=WIDTH, height=HEIGHT,
                          min_size=(900, 600), confirm_close=False)
    webview.start(debug=debug)


def main() -> int:
    try:
        launch()
    except DesktopUnavailable as e:
        print(f"[데스크톱 창 실패] {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
