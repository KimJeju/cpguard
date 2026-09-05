"""안전 해제 검증 — zip-slip / zip bomb 방어."""
import io
import zipfile

import pytest

import os

from cpguard.extract import UnsafeArchive, _longpath, safe_extract_zip


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


def test_long_path_extract(tmp_path):
    # Windows 260자(MAX_PATH) 를 넘기는 깊은 경로도 풀려야 한다(\\?\ 확장 경로).
    # 실제 대형 프로젝트(예: sparrow)에서 한 파일의 긴 경로가 해제 전체를 crash 시키던 회귀.
    deep = "/".join("seg%02d_padding_to_make_it_long" % i for i in range(9)) + "/f.js"
    assert len(deep) > 260
    z = _zip(tmp_path, [(deep, "const x=1;")])
    out = tmp_path / "out"
    assert safe_extract_zip(z, out) == 1
    # 존재 확인도 확장 경로로 — 일반 경로의 exists() 자체가 260자 한계에 걸린다.
    assert os.path.exists(_longpath(out / deep))


def test_long_path_file_is_found_and_scanned(tmp_path):
    r"""Windows MAX_PATH(260자) 넘는 파일이 탐색에서 조용히 빠지지 않는다.

    추출은 \?\ 확장 경로로 쓰면서 탐색(rglob)은 안 써서, 긴 경로 파일이
    스캔되지도 않고 무결성 보고에도 안 남던 회귀를 막는다("0건"=안전 오인).
    """
    import io
    import zipfile

    from cpguard.extract import safe_extract_zip
    from cpguard.scanner import scan_path

    deep = "/".join(["b" * 40] * 4)                     # 상대 경로만 240자 이상
    inner = f"{deep}/{'c' * 80}.js"
    assert len(inner) > 240
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(inner, "app.get('/x',(req,res)=>{eval(req.query.q)})")
    (tmp_path / "u.zip").write_bytes(buf.getvalue())

    assert safe_extract_zip(tmp_path / "u.zip", tmp_path / "src") == 1
    findings, report = scan_path(tmp_path / "src")
    assert report.scanned == 1, f"긴 경로 파일이 탐색에서 누락됨: {report.summary()}"
    assert any(f.rule_id == "js.code-injection" for f in findings)
    # 저장·표시 경로에 \?\ 접두가 새어 나가지 않는다
    assert not str(findings[0].sink.loc.file).startswith("\\?\\")
