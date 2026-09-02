"""로컬 대시보드 실행기.

설치형 배포에서 실행파일이 이걸 호출한다: DB 준비 -> 서버 기동 -> 브라우저 자동 오픈.
"""
from __future__ import annotations

import os
import threading
import webbrowser


def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = True) -> None:
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "cpguard.web.settings")

    import django
    django.setup()
    from django.core.management import call_command

    # 마이그레이션 파일 없이 모델에서 바로 테이블 생성(단일 사용자 로컬 앱)
    call_command("migrate", run_syncdb=True, verbosity=0, interactive=False)

    url = f"http://{host}:{port}/"
    if open_browser:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    print(f"CPGuard 대시보드: {url}  (종료: Ctrl+C)")
    call_command("runserver", f"{host}:{port}", use_reloader=False, verbosity=0)
