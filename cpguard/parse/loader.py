"""tree-sitter 문법 로드 + 소스 파싱.

이 모듈은 완성본이다(내가 깖). CST(concrete syntax tree)를 만들어 주고,
이걸 IR로 정규화하는 건 normalize.py / normalize_php.py / normalize_py.py /
normalize_cfam.py(Java·Kotlin·Go·C/C++·Swift·C#·Ruby).
"""
from __future__ import annotations

from pathlib import Path

import tree_sitter_c as _tsc
import tree_sitter_c_sharp as _tscs
import tree_sitter_cpp as _tscpp
import tree_sitter_go as _tsgo
import tree_sitter_java as _tsjava
import tree_sitter_javascript as _tsjs
import tree_sitter_kotlin as _tskt
import tree_sitter_php as _tsphp
import tree_sitter_python as _tspy
import tree_sitter_ruby as _tsrb
import tree_sitter_swift as _tsswift
import tree_sitter_typescript as _tsts
from tree_sitter import Language, Parser, Tree

_JS = Language(_tsjs.language())
_TS = Language(_tsts.language_typescript())
_TSX = Language(_tsts.language_tsx())
_PHP = Language(_tsphp.language_php())
_PY = Language(_tspy.language())
_JAVA = Language(_tsjava.language())
_KT = Language(_tskt.language())
_GO = Language(_tsgo.language())
_RB = Language(_tsrb.language())
_CPP = Language(_tscpp.language())
_C = Language(_tsc.language())
_SWIFT = Language(_tsswift.language())
_CS = Language(_tscs.language())

# 확장자 -> (Language, 문법이름). 문법이름은 정규화기 선택과 규칙 언어 매핑에 쓴다.
_BY_EXT: dict[str, tuple[Language, str]] = {
    ".js": (_JS, "javascript"),
    ".jsx": (_JS, "javascript"),
    ".mjs": (_JS, "javascript"),
    ".cjs": (_JS, "javascript"),
    ".ts": (_TS, "typescript"),
    ".tsx": (_TSX, "tsx"),
    ".php": (_PHP, "php"),
    ".phtml": (_PHP, "php"),
    ".inc": (_PHP, "php"),
    ".py": (_PY, "python"),
    ".pyw": (_PY, "python"),
    ".java": (_JAVA, "java"),
    ".kt": (_KT, "kotlin"),
    ".kts": (_KT, "kotlin"),
    ".go": (_GO, "go"),
    ".rb": (_RB, "ruby"),
    ".rake": (_RB, "ruby"),
    ".cpp": (_CPP, "cpp"),
    ".cc": (_CPP, "cpp"),
    ".cxx": (_CPP, "cpp"),
    ".hpp": (_CPP, "cpp"),
    ".hh": (_CPP, "cpp"),
    ".hxx": (_CPP, "cpp"),
    ".c": (_C, "c"),
    ".h": (_C, "c"),
    ".swift": (_SWIFT, "swift"),
    ".cs": (_CS, "csharp"),
}

SUPPORTED_EXTENSIONS = frozenset(_BY_EXT)

_GRAMMARS: dict[str, Language] = {
    "javascript": _JS, "typescript": _TS, "tsx": _TSX, "php": _PHP, "python": _PY,
    "java": _JAVA, "kotlin": _KT, "go": _GO, "ruby": _RB, "cpp": _CPP, "c": _C,
    "swift": _SWIFT, "csharp": _CS,
}

# 문법 이름과 규칙의 languages 필드는 다를 수 있다.
# .tsx 는 JSX 를 아는 별도 문법으로 파싱해야 하지만, 규칙 관점에서는 typescript 다.
# .c 는 C 문법으로 파싱하지만 sink(system/strcpy…)가 같으므로 cpp 규칙을 공유한다.
_RULE_LANGUAGE = {
    "javascript": "javascript",
    "typescript": "typescript",
    "tsx": "typescript",
    "php": "php",
    "python": "python",
    "java": "java",
    "kotlin": "kotlin",
    "go": "go",
    "ruby": "ruby",
    "cpp": "cpp",
    "c": "cpp",
    "swift": "swift",
    "csharp": "csharp",
}

# normalize_cfam 이 담당하는 문법들
CFAM_LANGUAGES = frozenset({"java", "kotlin", "go", "ruby", "cpp", "c", "swift", "csharp"})


def rule_language(grammar_name: str) -> str:
    """문법 이름 -> 규칙 매칭에 쓰는 언어 이름."""
    return _RULE_LANGUAGE.get(grammar_name, grammar_name)


class UnsupportedLanguage(ValueError):
    pass


def _resolve(ext: str) -> tuple[Language, str]:
    try:
        return _BY_EXT[ext.lower()]
    except KeyError:
        raise UnsupportedLanguage(f"지원하지 않는 확장자: {ext!r}")


def language_name_for(path: str | Path) -> str:
    """파일 경로 -> 문법 이름."""
    return _resolve(Path(path).suffix)[1]


def parse_source(src: str | bytes, *, language: str = "javascript") -> Tree:
    """소스 문자열/바이트를 파싱해 tree-sitter Tree 반환."""
    lang = _GRAMMARS.get(language)
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
