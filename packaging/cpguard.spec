# PyInstaller 스펙 — CPGuard 데스크톱 앱 번들
#
# 빌드:  pyinstaller packaging/cpguard.spec --noconfirm
# 산출:  dist/CPGuard/CPGuard.exe  (onedir — 시작이 빠르고 백신 오탐이 적다)
#
# Django 는 설정·앱을 문자열로 늦게 불러오므로 hiddenimports 로 명시해야 한다.
# tree-sitter 문법은 컴파일된 확장 모듈이라 collect_dynamic_libs 로 함께 담는다.

from PyInstaller.utils.hooks import (collect_all, collect_data_files,
                                     collect_dynamic_libs, collect_submodules)

datas = []
binaries = []
hiddenimports = []

# 우리 패키지의 데이터: 탐지 규칙, 웹 템플릿, 마이그레이션
datas += [
    ("../cpguard/specs", "cpguard/specs"),
    ("../cpguard/patterns", "cpguard/patterns"),
    ("../cpguard/web/templates", "cpguard/web/templates"),
    ("../cpguard/web/migrations", "cpguard/web/migrations"),
]

# tree-sitter 문법 (컴파일된 확장 모듈)
for mod in ("tree_sitter", "tree_sitter_javascript", "tree_sitter_typescript",
            "tree_sitter_php", "tree_sitter_python"):
    binaries += collect_dynamic_libs(mod)
    datas += collect_data_files(mod)
    hiddenimports.append(mod)

# Django 는 동적 임포트가 많다
# Django 는 템플릿태그·백엔드·체크 등을 문자열로 늦게 불러온다. 개별 지정으로는 계속
# 빠지는 것이 나오므로 서브모듈을 통째로 수집한다(내장 django 훅은 우리가 무력화했다).
hiddenimports += collect_submodules("django")
hiddenimports += collect_submodules("cpguard")
hiddenimports += [
    "cpguard.web.settings",
    "cpguard.web.urls",
    "cpguard.web.views",
    "cpguard.web.models",
    "django.contrib.contenttypes",
    "django.contrib.contenttypes.apps",
    "django.contrib.contenttypes.migrations",
    "django.db.backends.sqlite3",
    "django.db.backends.sqlite3.base",
    "django.template.backends.django",
    "django.middleware.security",
    "django.middleware.common",
    "django.middleware.csrf",
    "django.middleware.clickjacking",
    "django.core.management.commands.migrate",
    "django.core.management.commands.runserver",
    "yaml",
]
datas += collect_data_files("django", include_py_files=False)

# pywebview: 백엔드(edgechromium/winforms)를 실행 시점에 동적 로드하므로 통째로 담는다.
# Windows 백엔드는 pythonnet(clr) 위에서 동작한다.
for mod in ("webview", "clr_loader", "pythonnet"):
    try:
        d, b, h = collect_all(mod)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass
hiddenimports += [
    "webview.platforms.edgechromium",
    "webview.platforms.winforms",
    "clr",
]

# PDF 산출(reportlab) — 데이터/폰트 포함해 통째로 담는다
try:
    d, b, h = collect_all("reportlab")
    datas += d
    binaries += b
    hiddenimports += h
except Exception:
    pass

# 선택 의존성(있으면 담고 없으면 건너뜀) — LLM 프로바이더
for optional in ("anthropic", "openai", "google.genai"):
    try:
        hiddenimports += collect_submodules(optional)
    except Exception:
        pass

# conda 파이썬은 CPython 확장 모듈이 의존하는 DLL 을 Library/bin 에 둔다.
# PyInstaller 는 이 위치를 자동으로 뒤지지 않으므로 명시적으로 담아야 한다.
# 빠지면 번들에서 "DLL load failed while importing _ssl / _ctypes / _sqlite3" 로 죽는다.
import pathlib as _pl
import sys as _sys

# conda 채널마다 이름이 달라(ffi-8.dll vs libffi-8.dll) 두 형태를 모두 본다
_NEEDED = ("libssl-3*.dll", "libcrypto-3*.dll", "ffi*.dll", "libffi*.dll",
           "sqlite3.dll", "liblzma*.dll", "libbz2*.dll", "zlib*.dll",
           "libexpat*.dll", "libcrypto*.dll", "libssl*.dll",
           # VC++ 런타임 — 클린 머신엔 재배포판이 없다. 빌드머신엔 시스템에 깔려 있어
           # PyInstaller 가 일부만 담기 쉬우므로(특히 msvcp140.dll, vcruntime140_1.dll)
           # 전부 명시 동봉한다. 빠지면 클린 VM 에서 로더 단계에 조용히 죽는다.
           "vcruntime140*.dll", "msvcp140*.dll", "concrt140*.dll", "vccorlib140*.dll")
# 환경 루트와 Library/bin 양쪽을 뒤진다(conda 는 두 곳에 흩어 둔다)
for _dir in (_pl.Path(_sys.prefix), _pl.Path(_sys.prefix) / "Library" / "bin"):
    if _dir.is_dir():
        for _pat in _NEEDED:
            for _p in _dir.glob(_pat):
                binaries.append((str(_p), "."))

a = Analysis(
    ["../cpguard/desktop.py"],
    pathex=[".."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=["packaging/hooks"],
    excludes=["tkinter", "matplotlib", "numpy", "pytest", "PyInstaller"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="CPGuard",
    console=False,          # 창 앱이므로 콘솔 숨김
    disable_windowed_traceback=False,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,              # UPX 압축은 백신 오탐을 유발해 끈다
    name="CPGuard",
)
