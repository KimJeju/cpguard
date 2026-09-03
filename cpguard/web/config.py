"""로컬 설정(LLM API 키) 저장·적용.

키는 DATA_DIR/config.json 에 둔다(로컬 데스크톱 전용). 트리아지 프로바이더는
환경변수(ANTHROPIC_API_KEY 등)를 읽으므로, 앱 기동 시 apply_to_env() 로 옮긴다.
이미 환경변수로 설정돼 있으면 그쪽을 우선한다(운영 배포 대비).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# (id, 환경변수명, 표시이름)
KEYS = [
    ("anthropic", "ANTHROPIC_API_KEY", "Claude (Anthropic)"),
    ("openai", "OPENAI_API_KEY", "ChatGPT (OpenAI)"),
    ("gemini", "GEMINI_API_KEY", "Gemini (Google)"),
]


def _path() -> Path:
    from django.conf import settings
    return Path(settings.DATA_DIR) / "config.json"


def load() -> dict:
    try:
        return json.loads(_path().read_text(encoding="utf-8"))
    except Exception:
        return {}


def save(cfg: dict) -> None:
    p = _path()
    p.write_text(json.dumps(cfg, ensure_ascii=False, indent=2), encoding="utf-8")
    try:
        os.chmod(p, 0o600)  # 키 파일 권한 축소(가능한 플랫폼에서)
    except Exception:
        pass


def apply_to_env() -> None:
    """저장된 키를 환경변수로 적용. 이미 환경에 있으면 덮어쓰지 않는다."""
    cfg = load()
    for _cid, env, _label in KEYS:
        val = cfg.get(env)
        if val and not os.environ.get(env):
            os.environ[env] = val


def mask_key(v: str) -> str:
    """설정 화면에 저장된 키를 마스킹해 보여준다."""
    v = (v or "").strip()
    if len(v) <= 8:
        return "•" * len(v)
    return v[:4] + "•" * 8 + v[-4:]
