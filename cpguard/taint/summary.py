"""함수 오염 요약(summary).

프로시저간 분석의 핵심 자료구조. 함수 하나에 대해 다음 두 질문의 답을 담는다.

  1) param i 가 오염되면 → 리턴값도 오염되는가?      (returns_tainted)
  2) param i 가 오염되면 → 함수 안의 위험 지점에 닿는가? (sink_paths, 내부 경로 포함)
  3) 인자와 무관하게 항상 오염된 값을 리턴하는가?      (returns_source)
     예: function readInput(req){ return req.query.cmd; } 는 자기 안에서 오염을 만든다.

호출지점에서는 이 요약만 보면 되므로, 함수 본문을 매번 다시 분석하지 않는다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..report.finding import Step

#: 동봉 라이브러리 요약 위치.
SUMMARY_DIR = Path(__file__).resolve().parent.parent / "summaries"

PROPAGATE, BLOCK = "propagate", "block"


def user_summary_dir() -> Path:
    """사용자 요약 오버레이 위치. 규칙 오버레이(spec.user_spec_dir)와 같은 규약."""
    if env := os.environ.get("CPGUARD_SUMMARIES"):
        return Path(env)
    return Path(os.environ.get("CPGUARD_HOME", Path.home() / ".cpguard")) / "summaries"


@dataclass
class Summary:
    # 리턴값을 오염시키는 파라미터 인덱스 집합
    returns_tainted: set[int] = field(default_factory=set)
    # 파라미터 인덱스 -> 그 파라미터에서 시작해 위험 지점까지 가는 함수 내부 경로들
    sink_paths: dict[int, list[list[Step]]] = field(default_factory=dict)
    # 인자와 무관하게 함수 내부에서 오염을 만들어 리턴하는 경우, 그 내부 경로
    source_trace: list[Step] = field(default_factory=list)

    @property
    def returns_source(self) -> bool:
        return bool(self.source_trace)

    def is_empty(self) -> bool:
        return not self.returns_tainted and not self.sink_paths and not self.source_trace


@dataclass
class LibraryModel:
    """분석 대상 밖 함수(표준 라이브러리 등)의 동작 선언.

    엔진은 소스가 없는 함수를 만나면 과대근사하고 흐름을 '불확실'로 표시한다. 표준
    라이브러리처럼 동작이 확정된 함수는 여기서 답이 나오므로 그럴 필요가 없다.
    """

    #: 메서드 이름 -> (판정, 적용 언어). 언어가 비면 전 언어.
    by_method: dict[str, tuple[str, frozenset[str]]] = field(default_factory=dict)
    #: 점 경로 전체 -> (판정, 적용 언어). 정적 호출(String.format 등)용.
    by_path: dict[str, tuple[str, frozenset[str]]] = field(default_factory=dict)

    def verdict(self, path: str, languages: tuple[str, ...] | list[str] = ()) -> str | None:
        """'propagate' | 'block' | None(모름 -> 엔진이 과대근사).

        점 경로 전체가 먼저다. `String.format` 처럼 수신자가 타입 이름인 정적 호출은
        메서드 이름만 보면 다른 것과 섞인다.
        """
        for table, key in ((self.by_path, path), (self.by_method, path.rpartition(".")[2])):
            hit = table.get(key)
            if hit and (not hit[1] or hit[1] & set(languages)):
                return hit[0]
        return None


def _read_model(directory: Path, model: LibraryModel) -> None:
    """디렉터리의 yml 을 모델에 싣는다. 나중에 읽은 값이 앞의 값을 덮는다."""
    for p in sorted(directory.glob("*.yml")):
        try:
            d = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue                      # 사용자가 잘못 쓴 파일 하나로 분석이 멈추면 안 된다
        langs = frozenset(d.get("languages") or ())
        for verdict in (BLOCK, PROPAGATE):
            section = d.get(verdict) or {}
            for name in section.get("method") or ():
                model.by_method[name] = (verdict, langs)
            for name in section.get("name") or ():
                model.by_path[name] = (verdict, langs)


def load_library_model(directory: str | Path | None = None,
                       user_dir: str | Path | None = None) -> LibraryModel:
    """동봉 요약 + 사용자 오버레이. user_dir=False 로 오버레이를 끈다."""
    model = LibraryModel()
    _read_model(Path(directory) if directory else SUMMARY_DIR, model)
    if user_dir is not False:
        udir = Path(user_dir) if user_dir else user_summary_dir()
        if udir.is_dir():
            _read_model(udir, model)      # 사용자 값이 동봉 값을 덮는다
    return model
