"""패턴 규칙 엔진 검증 — 흐름 없이 단일 지점으로 판정하는 축."""
import pytest

from cpguard.patterns import load_pattern_rules, scan_text

RULES = load_pattern_rules()


def ids(src: str, language: str | None = None) -> set[str]:
    rules = RULES if language is None else [
        r for r in RULES if not r.languages or language in r.languages]
    return {f.rule_id for f in scan_text(src, "t.js", rules)}


def test_rules_loaded():
    assert len(RULES) >= 15
    assert all(r.id and r.cwe for r in RULES)


# ---------- 비밀정보 ----------

@pytest.mark.parametrize("rule_id,src", [
    ("secret.hardcoded-password", 'password="admin1234"'),
    ("secret.api-key", 'api_key = "sk_live_9f8a7b6c5d4e3f2a1b0c"'),
    ("secret.aws-access-key", 'key = "AKIAIOSFODNN7EXAMPLE"'),
    ("secret.private-key", "-----BEGIN RSA PRIVATE KEY-----"),
    ("secret.connection-string", 'u = "mongodb://root:s3cretpw@10.0.0.5:27017/db"'),
])
def test_secret_detected(rule_id, src):
    assert rule_id in ids(src)


@pytest.mark.parametrize("src", [
    'password = process.env.DB_PASSWORD',
    'password = os.environ["DB_PASSWORD"]',
    'password = "your_password_here"',
    'api_key = os.getenv("API_KEY")',
])
def test_env_lookup_is_not_a_secret(src):
    """환경변수에서 읽는 것은 하드코딩이 아니다."""
    found = ids(src)
    assert not {i for i in found if i.startswith("secret.")}


def test_fstring_connection_string_is_not_hardcoded():
    """f-string 으로 조립한 접속 문자열은 값이 소스에 없다."""
    src = 'DB_URL = f"mysql+pymysql://{user}:{passwd}@{host}:{port}/{db}"'
    assert "secret.connection-string" not in ids(src)


# ---------- 웹 위생 ----------

@pytest.mark.parametrize("rule_id,src", [
    ("web.react-dangerous-html", "<div dangerouslySetInnerHTML={{__html: raw}} />"),
    ("web.inner-html-assign", "el.innerHTML = userInput;"),
    ("web.document-write", "document.write(name);"),
    ("web.token-in-web-storage",
     "sessionStorage.setItem('access_token', res.token);"),
    ("web.tls-verification-disabled", "const a = {rejectUnauthorized: false};"),
    ("web.insecure-cookie-flags", "res.cookie('s', v, {httpOnly: false});"),
])
def test_web_hygiene_detected(rule_id, src):
    assert rule_id in ids(src, "javascript")


def test_sanitized_dangerous_html_is_skipped():
    src = "<div dangerouslySetInnerHTML={{__html: DOMPurify.sanitize(raw)}} />"
    assert "web.react-dangerous-html" not in ids(src, "javascript")


def test_textcontent_assignment_is_safe():
    assert "web.inner-html-assign" not in ids("el.textContent = userInput;", "javascript")


# ---------- 암호 ----------

@pytest.mark.parametrize("rule_id,src", [
    ("crypto.weak-hash", 'crypto.createHash("md5")'),
    ("crypto.weak-hash", "hashlib.sha1(data)"),
    ("crypto.weak-cipher", 'Cipher.getInstance("AES/ECB/PKCS5Padding")'),
    ("crypto.insecure-random", "const token = Math.random().toString(36);"),
])
def test_crypto_detected(rule_id, src):
    assert rule_id in ids(src)


def test_strong_hash_not_flagged():
    assert "crypto.weak-hash" not in ids('crypto.createHash("sha256")')


# ---------- 운영 위생 ----------

@pytest.mark.parametrize("rule_id,src", [
    ("hygiene.debug-code-left", "  debugger;"),
    ("hygiene.debug-code-left", "  var_dump($x);"),
    ("hygiene.debug-enabled", "DEBUG = True"),
])
def test_hygiene_detected(rule_id, src):
    assert rule_id in ids(src)


# ---------- 공통 동작 ----------

def test_comment_lines_are_skipped_by_default():
    """주석 안의 예시 코드로 오탐이 나면 안 된다."""
    assert "web.inner-html-assign" not in ids("// el.innerHTML = userInput;", "javascript")


def test_finding_has_location_and_snippet():
    src = "line one\npassword=\"hunter22\"\nline three"
    f = [x for x in scan_text(src, "a.py", RULES)
         if x.rule_id == "secret.hardcoded-password"][0]
    assert f.steps[0].loc.start_line == 2
    assert "hunter22" in f.steps[0].code
    assert f.steps[0].kind == "match"


def test_language_filter():
    js_only = [r for r in RULES if r.languages == ["javascript", "typescript"]]
    assert js_only, "언어 한정 규칙이 있어야 한다"
    assert "web.react-dangerous-html" not in ids("dangerouslySetInnerHTML", "python")
