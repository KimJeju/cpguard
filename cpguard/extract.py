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

        for i in infos:
            z.extract(i, dest)

    return len(infos)
