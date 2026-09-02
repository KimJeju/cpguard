"""안전 해제 검증 — zip-slip / zip bomb 방어."""
import io
import zipfile

import pytest

from cpguard.extract import UnsafeArchive, safe_extract_zip


def _zip(tmp_path, entries):
    p = tmp_path / "a.zip"
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in entries:
            z.writestr(name, data)
    return p


def test_normal_extract(tmp_path):
    z = _zip(tmp_path, [("app/index.js", "const x=1;")])
    out = tmp_path / "out"
    assert safe_extract_zip(z, out) == 1
    assert (out / "app" / "index.js").exists()


def test_zip_slip_blocked(tmp_path):
    z = _zip(tmp_path, [("../evil.js", "pwned")])
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(z, tmp_path / "out")


def test_absolute_path_blocked(tmp_path):
    z = _zip(tmp_path, [("/etc/passwd", "x")])
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(z, tmp_path / "out")


def test_zip_bomb_ratio_blocked(tmp_path):
    z = _zip(tmp_path, [("big.txt", "A" * 5_000_000)])
    with pytest.raises(UnsafeArchive):
        safe_extract_zip(z, tmp_path / "out")
