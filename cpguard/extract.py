"""업로드 zip 안전 해제.

진단 도구가 업로드 파일로 털리면 안 되므로 해제 단계에서 다음을 막는다.
  - zip-slip : 항목 이름의 ../ 로 대상 디렉터리 밖에 쓰는 공격
  - zip bomb : 압축률/총 용량/파일 수 폭탄
  - 절대경로·드라이브 경로 항목
"""
from __future__ import annotations

import os
import zipfile
from pathlib import Path

# 대형 코드베이스(수만 파일·수 GB)를 받되 zip 폭탄은 막는다. 환경변수로 상향 조정 가능.
#   CPGUARD_MAX_FILES / CPGUARD_MAX_BYTES / CPGUARD_MAX_RATIO
MAX_FILES = int(os.environ.get("CPGUARD_MAX_FILES", "200000"))
MAX_TOTAL_BYTES = int(os.environ.get("CPGUARD_MAX_BYTES", str(8 * 1024 * 1024 * 1024)))  # 8GB
MAX_COMPRESSION_RATIO = int(os.environ.get("CPGUARD_MAX_RATIO", "200"))  # 압축률 초과 = 폭탄 의심


class UnsafeArchive(ValueError):
    """안전하지 않은 아카이브."""


def safe_extract_zip(zip_path: str | Path, dest: str | Path) -> int:
    """zip 을 dest 아래로 안전하게 푼다. 반환: 푼 파일 수."""
    dest = Path(dest).resolve()
    dest.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(zip_path) as z:
        infos = [i for i in z.infolist() if not i.is_dir()]

        if len(infos) > MAX_FILES:
            raise UnsafeArchive(f"파일 수 초과: {len(infos)} > {MAX_FILES}")

        total = sum(i.file_size for i in infos)
        if total > MAX_TOTAL_BYTES:
            raise UnsafeArchive(f"해제 용량 초과: {total} bytes")

        compressed = sum(i.compress_size for i in infos) or 1
        if total / compressed > MAX_COMPRESSION_RATIO:
            raise UnsafeArchive(f"압축률 비정상(zip bomb 의심): {total / compressed:.0f}x")

        for i in infos:
            name = i.filename.replace("\\", "/")
            if name.startswith("/") or ".." in Path(name).parts or ":" in name.split("/")[0]:
                raise UnsafeArchive(f"위험한 경로 항목: {i.filename!r}")
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest)):
                raise UnsafeArchive(f"대상 디렉터리 밖 경로(zip-slip): {i.filename!r}")

        # 위의 크기·압축률 검사는 아카이브가 스스로 신고한 값을 본다. 헤더는 거짓말할 수
        # 있으므로 실제로 쓰는 바이트를 세어 같은 상한을 다시 건다 — 이게 없으면 1KB 라고
        # 적힌 항목이 100GB 로 부풀어도 그대로 디스크에 쏟아진다.
        budget = MAX_TOTAL_BYTES
        for i in infos:
            name = i.filename.replace("\\", "/")
            target = dest / name
            os.makedirs(_longpath(target.parent), exist_ok=True)
            with z.open(i) as src, open(_longpath(target), "wb") as out:
                budget -= _copy_bounded(src, out, budget, i.filename)

    return len(infos)


def _copy_bounded(src, out, budget: int, name: str) -> int:
    """남은 예산 안에서만 복사한다. 헤더가 신고한 크기는 믿지 않는다."""
    written = 0
    while True:
        chunk = src.read(1 << 20)
        if not chunk:
            return written
        written += len(chunk)
        if written > budget:
            raise UnsafeArchive(
                f"해제 용량 초과(헤더 신고값과 다름, zip bomb 의심): {name!r}")
        out.write(chunk)


LONG_PREFIX = "\\\\?\\"


def _longpath(p: Path) -> str:
    r"""Windows 260자 경로 한계(MAX_PATH) 우회. 깊게 중첩된 대형 프로젝트를 풀 때
    한 파일의 긴 경로가 해제 전체를 crash 시키던 문제를 막는다(\\?\ 확장 경로).

    쓰기뿐 아니라 '탐색'에도 필요하다 — 접두 없이 rglob 하면 260자 넘는 파일은
    아예 열거되지 않아 조용히 누락된다(scanner.iter_* 참고)."""
    s = os.path.abspath(str(p))
    if os.name == "nt" and not s.startswith(LONG_PREFIX):
        s = LONG_PREFIX + s
    return s


def longpath(p) -> str:
    r"""공개 별칭 — \\?\ 확장 경로 문자열."""
    return _longpath(Path(p))


def strip_longpath(s) -> str:
    r"""\\?\ 접두 제거. 저장·표시용 경로에 확장 접두가 새어 나가지 않게."""
    s = str(s)
    return s[len(LONG_PREFIX):] if s.startswith(LONG_PREFIX) else s
