"""로컬 데스크톱 대시보드용 Django 설정.

사용자 홈의 ~/.cpguard 에 DB·업로드를 둔다(설치형 배포 시 쓰기 가능한 위치).
외부 노출용이 아니라 로컬 전용이므로 127.0.0.1 만 허용한다.
"""
from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("CPGUARD_HOME", Path.home() / ".cpguard"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# 로컬 전용 키. 없으면 생성해 보관한다.
_key_file = DATA_DIR / "secret.key"
if not _key_file.exists():
    _key_file.write_text(secrets.token_urlsafe(50), encoding="utf-8")
SECRET_KEY = _key_file.read_text(encoding="utf-8").strip()

DEBUG = False
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "cpguard.web",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "cpguard.web.urls"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [BASE_DIR / "templates"],
    "APP_DIRS": False,
    "OPTIONS": {"context_processors": ["django.template.context_processors.request"]},
}]

# DB 선택:
#  - 기본(로컬 데스크톱): SQLite(내장). WAL+동시성 pragma 로 대량 쓰기/조회를 견디게 튜닝.
#  - 서버/팀 배포: 환경변수 CPGUARD_DATABASE_URL 에 postgres URL 을 주면 PostgreSQL 사용
#    (psycopg 는 서버에 별도 설치; 오프라인 데스크톱 설치본에는 번들하지 않는다).
def _database_config():
    url = os.environ.get("CPGUARD_DATABASE_URL", "").strip()
    if url.startswith(("postgres://", "postgresql://")):
        from urllib.parse import unquote, urlparse
        u = urlparse(url)
        return {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": (u.path or "/cpguard").lstrip("/") or "cpguard",
            "USER": unquote(u.username or ""),
            "PASSWORD": unquote(u.password or ""),
            "HOST": u.hostname or "localhost",
            "PORT": str(u.port or 5432),
            "CONN_MAX_AGE": 60,
        }
    return {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": str(DATA_DIR / "cpguard.db"),
        "OPTIONS": {
            # 동시 읽기+쓰기 견디게: WAL 저널, 합리적 동기화, 락 타임아웃, 캐시.
            "init_command": (
                "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; "
                "PRAGMA busy_timeout=5000; PRAGMA cache_size=-16000; PRAGMA foreign_keys=ON;"
            ),
            "transaction_mode": "IMMEDIATE",
        },
    }


DATABASES = {"default": _database_config()}

STATIC_URL = "/static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
USE_TZ = True
TIME_ZONE = "Asia/Seoul"

# zip 업로드 허용 크기 (해제 단계에서 다시 검증한다)
DATA_UPLOAD_MAX_MEMORY_SIZE = 200 * 1024 * 1024
FILE_UPLOAD_MAX_MEMORY_SIZE = 10 * 1024 * 1024

# Django 는 우리 LOGGING 을 적용하기 전에 DEFAULT_LOGGING(관리자 메일 핸들러 포함)을
# 먼저 구성한다. 로컬 데스크톱 앱에는 불필요하고, 실행 파일로 묶으면 메일 모듈이 없어
# 기동 자체가 실패한다. LOGGING_CONFIG=None 으로 Django 의 로깅 구성을 건너뛰고
# 직접 최소 설정만 한다.
LOGGING_CONFIG = None
logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
