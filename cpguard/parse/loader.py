"""tree-sitter 문법 로드 + 소스 파싱.

이 모듈은 완성본이다(내가 깖). CST(concrete syntax tree)를 만들어 주고,
이걸 IR로 정규화하는 건 normalize.py(네가 구현).
"""
from __future__ import annotations

from pathlib import Path

import tree_sitter_javascript as _tsjs
import tree_sitter_php as _tsphp
import tree_sitter_typescript as _tsts
from tree_sitter import Language, Parser, Tree

_JS = Language(_tsjs.language())
_TS = Language(_tsts.language_typescript())
_TSX = Language(_tsts.language_tsx())
_PHP = Language(_tsphp.language_php())

# 확장자 -> (Language, 언어이름). 언어이름은 taint 스펙의 languages 필드와 매칭된다.
_BY_EXT: dict[str, tuple[Language, str]] = {
    ".js": (_JS, "javascript"),
    ".jsx": (_JS, "javascript"),
    ".mjs": (_JS, "javascript"),
    ".cjs": (_JS, "javascript"),
    ".ts": (_TS, "typescript"),
    ".tsx": (_TSX, "typescript"),
    ".php": (_PHP, "php"),
    ".phtml": (_PHP, "php"),
    ".inc": (_PHP, "php"),
}

SUPPORTED_EXTENSIONS = frozenset(_BY_EXT)


class UnsupportedLanguage(ValueError):
    pass


def _resolve(ext: str) -> tuple[Language, str]:
    try:
        return _BY_EXT[ext.lower()]
    except KeyError:
        raise UnsupportedLanguage(f"지원하지 않는 확장자: {ext!r}")


def language_name_for(path: str | Path) -> str:
    """파일 경로 -> 'javascript' | 'typescript'."""
    return _resolve(Path(path).suffix)[1]


def parse_source(src: str | bytes, *, language: str = "javascript") -> Tree:
    """소스 문자열/바이트를 파싱해 tree-sitter Tree 반환.

    language: 'javascript' | 'typescript' | 'tsx' | 'php'.
    """
    lang = {"javascript": _JS, "typescript": _TS, "tsx": _TSX, "php": _PHP}.get(language)
    if lang is None:
        raise UnsupportedLanguage(f"알 수 없는 언어: {language!r}")
    if isinstance(src, str):
        src = src.encode("utf-8")
    return Parser(lang).parse(src)


def parse_file(path: str | Path) -> Tree:
    """파일을 확장자 기준으로 파싱해 Tree 반환."""
    path = Path(path)
    lang, _ = _resolve(path.suffix)
    return Parser(lang).parse(path.read_bytes())
