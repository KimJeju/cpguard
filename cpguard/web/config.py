"""로컬 설정(LLM API 키) 저장·적용.

키는 DATA_DIR/config.json 에 둔다(로컬 데스크톱 전용). 트리아지 프로바이더는
환경변수(ANTHROPIC_API_KEY 등)를 읽으므로, 앱 기동 시 apply_to_env() 로 옮긴다.
이미 환경변수로 설정돼 있으면 그쪽을 우선한다(운영 배포 대비).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

# (id, 환경변수명, 표시이름, 프로바이더명)  — 프로바이더명은 triage.ask(provider=) 와 일치
KEYS = [
    ("anthropic", "ANTHROPIC_API_KEY", "Claude (Anthropic)", "claude"),
    ("openai", "OPENAI_API_KEY", "ChatGPT (OpenAI)", "openai"),
    ("gemini", "GEMINI_API_KEY", "Gemini (Google)", "gemini"),
]

# 키는 아니지만 프로바이더가 환경변수로 읽는 선택 설정.
# ANTHROPIC_WORKSPACE_ID: identity-linked(신원 연동) Claude 키에 필요한 워크스페이스 ID.
EXTRA_ENV = [
    ("anthropic_workspace", "ANTHROPIC_WORKSPACE_ID", "Claude 워크스페이스 ID (신원 연동 키만)"),
]

# 보고서 메타 — PDF 표지·개정이력에 들어가는 입력값. (키, 표시이름, 플레이스홀더)
# config.json 의 "report" 객체에 저장한다. 비우면 PDF 는 기본값(CPGuard 등)을 쓴다.
REPORT_FIELDS = [
    ("author", "작성자", "예: 홍길동 (보안팀)"),
    ("org", "수행 기관/회사", "예: ○○시큐어"),
    ("client", "발주처/고객", "예: ○○공사 정보보안팀"),
    ("tester", "진단 담당자", "예: 홍길동, 김철수"),
    ("period", "진단 수행 기간", "예: 2026.08.01 ~ 2026.08.20"),
    ("version", "보고서 버전", "예: 1.0"),
]


def report_meta() -> dict:
    """저장된 보고서 메타(빈 값은 제외)."""
    r = load().get("report") or {}
    return {k: (r.get(k) or "").strip() for k, _l, _p in REPORT_FIELDS if (r.get(k) or "").strip()}


# 설정 화면 모델 선택 후보(자유 입력도 허용). 빈 값 = 프로바이더 기본 모델.
MODEL_OPTIONS = {
    "claude": ["claude-opus-5", "claude-sonnet-5", "claude-haiku-4-5"],
    "openai": ["gpt-4o", "gpt-4o-mini"],
    "gemini": ["gemini-3.6-flash", "gemini-3.6-pro"],
}


def models() -> dict:
    """프로바이더명 -> 모델 오버라이드. 없으면 빈 dict."""
    return load().get("models") or {}


def model_for(provider_name: str | None) -> str | None:
    """설정된 모델 오버라이드(없으면 None → 프로바이더 기본)."""
    if not provider_name:
        return None
    return (models().get(provider_name) or "").strip() or None


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
    for _cid, env, _label, _pname in KEYS:
        val = cfg.get(env)
        if val and not os.environ.get(env):
            os.environ[env] = val
    for _cid, env, _label in EXTRA_ENV:
        val = cfg.get(env)
        if val and not os.environ.get(env):
            os.environ[env] = val


def mask_key(v: str) -> str:
    """설정 화면에 저장된 키를 마스킹해 보여준다."""
    v = (v or "").strip()
    if len(v) <= 8:
        return "•" * len(v)
    return v[:4] + "•" * 8 + v[-4:]
