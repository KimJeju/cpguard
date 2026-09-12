"""유형별 조치 권고·안전 예시 — 규칙 데이터에서 직접 쓰는 경량 테이블.

원래 report/pdf.py 안에 있었으나, reportlab·폰트를 끌어오는 PDF 작성기에 묶여 있어
MCP `explain` 이 가져다 쓸 수 없었다. 여기로 분리한다 — 이 모듈은 **i18n(딕셔너리
뿐)만 참조**하고 reportlab 을 import 하지 않는다. pdf.py 는 여기서 다시 가져다 쓴다.

테스트 tests/test_remediation_map.py 가 모든 규칙의 매핑을 강제한다.
"""
from __future__ import annotations

from ..i18n import DEFAULT_REM_EN, REMEDIATION_EN

# 유형별 조치 권고 (rule_id 접미사 기준). (제목, 설명, 조치 권고, 안전 예시)
REMEDIATION = {
    "sqli": ("SQL 주입 (SQL Injection)",
             "사용자 입력이 검증 없이 SQL 질의에 문자열로 결합되어, 공격자가 쿼리 구조를 변경할 수 있습니다.",
             "문자열 결합 대신 파라미터 바인딩(Prepared Statement / 파라미터화 쿼리)을 사용합니다. ORM 사용 시 원시 쿼리 결합을 피합니다.",
             "db.query('SELECT * FROM users WHERE id = ?', [userId])"),
    "command-injection": ("명령어 삽입 (OS Command Injection)",
             "사용자 입력이 셸 명령 실행 함수로 전달되어 임의 명령이 실행될 수 있습니다.",
             "셸을 거치는 exec 대신 execFile/spawn 등에 명령과 인자를 분리해 전달하고, 입력값은 허용목록으로 검증합니다.",
             "child_process.execFile('convert', [inputPath, outputPath])"),
    "xss": ("크로스사이트 스크립팅 (XSS)",
             "사용자 입력이 이스케이프 없이 HTML 응답에 출력되어 스크립트가 실행될 수 있습니다.",
             "출력 시 컨텍스트에 맞는 이스케이프(HTML/속성/JS)를 적용하고, 템플릿 엔진의 자동 이스케이프를 사용합니다. innerHTML 대신 textContent 를 씁니다.",
             "el.textContent = userInput  // innerHTML 금지"),
    "path-traversal": ("경로 조작 (Path Traversal)",
             "사용자 입력이 파일 경로에 사용되어 상위 디렉터리(../) 접근이 가능할 수 있습니다.",
             "기준 디렉터리로 정규화(resolve) 후 접두 검사를 하고, 파일명은 허용목록/화이트리스트로 제한합니다.",
             "p = path.resolve(base, name); if(!p.startsWith(base)) throw"),
    "ssrf": ("서버측 요청 위조 (SSRF)",
             "사용자가 지정한 URL 로 서버가 요청을 보내 내부망 자원에 접근당할 수 있습니다.",
             "대상 호스트를 허용목록으로 제한하고, 사설 IP/메타데이터 주소(169.254.169.254 등)를 차단합니다.",
             "if(!ALLOWED_HOSTS.has(new URL(url).host)) reject()"),
    "code-injection": ("코드 삽입 (Code Injection)",
             "사용자 입력이 eval 등 동적 코드 실행에 전달되어 임의 코드가 실행될 수 있습니다.",
             "eval/new Function/동적 실행을 제거합니다. 데이터 파싱은 JSON.parse 등 안전한 대안을 사용합니다.",
             "const data = JSON.parse(input)  // eval 금지"),
    "file-inclusion": ("파일 삽입 (File Inclusion)",
             "사용자 입력이 include/require 경로에 사용되어 임의 파일이 포함될 수 있습니다.",
             "동적 포함 경로를 허용목록으로 제한하고 사용자 입력을 직접 경로로 쓰지 않습니다.",
             "$allowed = ['home','about']; include $allowed[$page] . '.php';"),
    "open-redirect": ("오픈 리다이렉트 (Open Redirect)",
             "사용자 입력이 리다이렉트 대상으로 사용되어 피싱에 악용될 수 있습니다.",
             "리다이렉트 대상을 내부 상대경로 또는 허용목록으로 제한합니다.",
             "if(!target.startsWith('/')) target = '/'"),
    "secret": ("하드코딩된 비밀정보 (Hardcoded Secret)",
             "비밀번호·API 키·토큰이 소스에 하드코딩되어 유출 위험이 있습니다.",
             "비밀정보는 환경변수·비밀관리(Secret Manager)로 분리하고, 노출된 키는 즉시 폐기·교체합니다.",
             "apiKey = process.env.API_KEY"),
    "pii": ("개인정보 노출 (PII)",
             "주민번호·카드번호·연락처 등 개인정보가 소스/설정에 포함되어 있습니다.",
             "실데이터를 소스에서 제거하고, 저장 시 암호화·마스킹을 적용합니다.",
             "// 실데이터 대신 환경/보안저장소 참조"),
    "tls": ("TLS 검증 비활성화",
            "인증서 검증을 끄면 중간자 공격에 노출됩니다.",
            "인증서 검증을 활성화하고, 필요한 내부 CA 는 신뢰저장소에 등록합니다.",
            "verify=True  // rejectUnauthorized: true"),
    "crypto": ("취약한 암호/해시",
               "MD5/SHA-1/DES/ECB 등 취약한 알고리즘 사용이 발견되었습니다.",
               "SHA-256 이상, AES-GCM 등 안전한 알고리즘으로 교체하고 비밀번호는 bcrypt/argon2 로 해시합니다.",
               "hashlib.sha256(x)  // bcrypt for passwords"),
    "deserialization": ("안전하지 않은 역직렬화 (Insecure Deserialization)",
             "신뢰할 수 없는 데이터가 객체 역직렬화에 사용되어 임의 코드 실행으로 이어질 수 있습니다.",
             "역직렬화 대상 클래스를 허용목록으로 제한하거나 JSON 등 데이터 전용 포맷으로 교체하고, 서명·무결성 검증을 함께 적용합니다.",
             "new ObjectMapper().readValue(body, Dto.class)"),
    "ldap-injection": ("LDAP 삽입 (LDAP Injection)",
             "사용자 입력이 LDAP 검색 필터에 결합되어 조회 조건을 변경할 수 있습니다.",
             "필터에 넣는 값은 RFC 4515 규칙으로 이스케이프하고, 가능하면 바인딩을 지원하는 API 를 사용합니다.",
             "(uid= + escapeLDAP(user) + )"),
    "xpath-injection": ("XPath 삽입 (XPath Injection)",
             "사용자 입력이 XPath 식에 결합되어 질의 구조를 바꿀 수 있습니다.",
             "XPathVariableResolver 등 변수 바인딩을 사용하고 문자열 결합을 제거합니다.",
             "xpath.setXPathVariableResolver(v);  /user[@id=$id]"),
    "buffer-overflow": ("버퍼 오버플로 (Buffer Overflow)",
             "길이 검사 없는 복사 함수가 사용되어 인접 메모리를 덮어쓸 수 있습니다.",
             "strcpy/strcat/sprintf/gets 대신 길이를 받는 함수를 쓰고, 목적지 버퍼 크기를 명시적으로 검사합니다.",
             "snprintf(dst, sizeof(dst), \"%s\", src)"),
    "format-string": ("포맷 스트링 (Format String)",
             "사용자 입력이 서식 문자열 자리에 직접 들어가 메모리 노출·변조가 가능합니다.",
             "서식 문자열은 상수로 고정하고 사용자 입력은 인자로만 전달합니다.",
             "printf(\"%s\", user)"),
    "library-injection": ("라이브러리 삽입 (Library Injection)",
             "사용자 입력이 동적 라이브러리 적재 경로에 사용되어 임의 모듈이 로드될 수 있습니다.",
             "적재 경로를 절대경로·허용목록으로 고정하고 서명 검증 후 로드합니다.",
             "dlopen(\"/opt/app/lib/plugin.so\", RTLD_NOW)"),
    "intent-redirect": ("인텐트 리다이렉션 (Intent Redirection)",
             "외부에서 받은 Intent 를 검증 없이 다시 실행해 비공개 컴포넌트가 호출될 수 있습니다.",
             "전달받은 Intent 를 그대로 실행하지 않고 대상 컴포넌트를 허용목록으로 검사합니다.",
             "if (target.component in ALLOWED) startActivity(target)"),
    "webview": ("WebView 위험 설정",
             "JavaScript 실행·파일 접근·JS 브리지가 열려 있어 원격 콘텐츠가 앱 권한으로 동작할 수 있습니다.",
             "필요 없으면 JavaScript·파일 접근을 끄고, JS 브리지는 신뢰 가능한 로컬 콘텐츠에만 노출합니다.",
             "settings.allowFileAccess = false"),
    "token-storage": ("인증 토큰의 웹 스토리지 저장",
             "토큰을 localStorage/sessionStorage 에 두면 XSS 한 건으로 곧바로 탈취됩니다.",
             "토큰은 HttpOnly·Secure·SameSite 쿠키로 옮겨 스크립트에서 읽지 못하게 합니다.",
             "Set-Cookie: token=...; HttpOnly; Secure; SameSite=Lax"),
    "cookie-flags": ("쿠키 보안 속성 누락",
             "Secure·HttpOnly·SameSite 가 빠져 평문 전송·스크립트 접근·CSRF 에 노출됩니다.",
             "세션 쿠키에 Secure·HttpOnly·SameSite 를 모두 지정하고, 필요하면 __Host- 접두를 사용합니다.",
             "res.cookie('sid', v, {secure:true, httpOnly:true, sameSite:'lax'})"),
    "debug": ("디버그 코드·설정 잔존",
             "운영 코드에 디버그 출력·디버그 모드가 남아 내부 정보와 스택트레이스가 노출됩니다.",
             "배포 전 디버그 플래그를 끄고 디버그 출력을 제거하며, 오류 화면은 일반화된 메시지로 대체합니다.",
             "DEBUG = False"),
    "comment-leak": ("주석 내 정보 노출",
             "소스 주석에 계정·내부 경로·미조치 사항이 남아 공격에 활용될 수 있습니다.",
             "배포 산출물에서 내부 정보가 담긴 주석을 제거하고, 미조치 사항은 이슈 트래커로 옮깁니다.",
             "// 상세 내용은 이슈 트래커 참조"),
    "hardcoded-connection": ("접속 정보 하드코딩",
             "DB·메일·디렉터리 서비스 접속 문자열과 계정이 소스에 그대로 있어 유출 시 즉시 악용됩니다.",
             "접속 정보를 환경변수·비밀관리로 분리하고, 노출된 계정은 즉시 교체합니다.",
             "url = os.environ['DB_URL']"),
    "default-account": ("기본·시험 계정 사용",
             "admin/test 같은 기본 계정과 추측 가능한 비밀번호가 소스에 남아 있습니다.",
             "기본·시험 계정을 제거하고, 운영 계정은 비밀번호 정책과 최소권한 원칙에 맞게 발급합니다.",
             "user = os.environ['APP_USER']"),
    "dev-path": ("개발자 로컬 경로 노출",
             "개발 PC 의 절대경로가 남아 내부 구조·사용자명이 드러나고 운영 환경에서 동작하지 않습니다.",
             "경로를 설정값·상대경로로 바꾸고 빌드 산출물에서 절대경로를 제거합니다.",
             "BASE = os.environ.get('APP_HOME', '/opt/app')"),
    "dependency": ("알려진 취약점이 있는 오픈소스 컴포넌트",
             "사용 중인 오픈소스 컴포넌트에 공개된 취약점(CVE)이 있어, 해당 취약점이 그대로 서비스에 노출됩니다.",
             "취약점이 해결된 상위 버전으로 갱신합니다. 즉시 갱신이 어려우면 해당 기능의 노출을 차단하고 컴포넌트 목록(SBOM)을 관리해 재발을 막습니다.",
             "// package.json / pom.xml 에서 해당 컴포넌트를 수정 버전으로 고정"),
    "internal-info": ("내부 구성 정보 노출",
             "사설 IP·관리자 경로 등 내부 정보가 소스에 하드코딩되어 정찰에 활용됩니다.",
             "내부 주소·관리자 경로를 설정으로 분리하고, 관리자 화면은 접근통제(허용 IP·인증)로 보호합니다.",
             "ADMIN_PATH = os.environ['ADMIN_PATH']"),
}
_DEFAULT_REM = ("보안약점", "탐지된 유형에 대한 조치가 필요합니다.",
                "해당 CWE 의 권고사항에 따라 입력 검증·출력 인코딩·최소권한 원칙을 적용합니다.", "")


#: 유형별 '취약한 코드 예시'. 조치 권고 옆에 고치기 전 모습을 같이 실어야 발주처 개발자가
#: 자기 코드에서 무엇을 찾아야 하는지 안다. 코드라 번역하지 않는다(한/영 공용).
VULN_EXAMPLE = {
    "sqli": "db.query(\"SELECT * FROM users WHERE id = \" + userId)",
    "command-injection": "exec(\"convert \" + req.query.file)",
    "xss": "el.innerHTML = userInput",
    "path-traversal": "readFile(base + req.query.name)",
    "ssrf": "fetch(req.query.url)",
    "code-injection": "eval(req.body.expr)",
    "file-inclusion": "include($_GET['page'] . '.php');",
    "open-redirect": "res.redirect(req.query.next)",
    "secret": "apiKey = \"sk-live-8f2c9a...\"",
    "pii": "TEST_USER = {\"rrn\": \"900101-1234567\"}",
    "tls": "requests.get(url, verify=False)",
    "crypto": "hashlib.md5(password).hexdigest()",
    "deserialization": "new ObjectInputStream(req.getInputStream()).readObject()",
    "ldap-injection": "\"(uid=\" + request.getParameter(\"user\") + \")\"",
    "xpath-injection": "\"/user[@id='\" + id + \"']\"",
    "buffer-overflow": "char dst[64]; strcpy(dst, argv[1]);",
    "format-string": "printf(user);",
    "library-injection": "dlopen(user_input, RTLD_NOW)",
    "intent-redirect": "startActivity(intent.getParcelableExtra(\"forward\"))",
    "webview": "settings.javaScriptEnabled = true; addJavascriptInterface(obj, \"app\")",
    "token-storage": "localStorage.setItem('accessToken', token)",
    "cookie-flags": "res.cookie('sid', v)",
    "debug": "DEBUG = True",
    "comment-leak": "// TODO: 임시 관리자 admin / admin1234",
    "hardcoded-connection": "jdbc:oracle:thin:scott/tiger@10.0.0.5:1521:ORCL",
    "default-account": "user = \"admin\"; password = \"admin1234\"",
    "dev-path": "BASE = \"C:\\\\Users\\\\hong\\\\workspace\\\\app\"",
    "internal-info": "ADMIN_URL = \"http://10.10.20.31/adminPage\"",
    "dependency": "\"lodash\": \"4.17.15\"   // CVE-2020-8203",
}

#: 접미 매칭으로는 조치 유형이 안 잡히는 규칙. 여기 없으면 일반 문구로 떨어지므로
#: tests/test_remediation_map.py 가 미매핑 규칙을 실패로 잡는다.
_EXPLICIT_KEY = {
    "sca.vulnerable-dependency": "dependency",
    "infra.ado-connection": "hardcoded-connection",
    "infra.jdbc-connection": "hardcoded-connection",
    "infra.oracle-tns": "hardcoded-connection",
    "infra.smtp-ldap-bind": "hardcoded-connection",
    "infra.default-test-account": "default-account",
    "infra.developer-local-path": "dev-path",
    "infra.private-ip": "internal-info",
    "infra.admin-path-hardcoded": "internal-info",
    "infra.command-execution-api": "command-injection",
    "infra.webview-dangerous-setting": "webview",
    "hygiene.debug-code-left": "debug",
    "hygiene.debug-enabled": "debug",
    "hygiene.kr-leftover-comment": "comment-leak",
    "web.document-write": "xss",
    "web.inner-html-assign": "xss",
    "web.react-dangerous-html": "xss",
    "web.insecure-cookie-flags": "cookie-flags",
    "web.token-in-web-storage": "token-storage",
}


def rule_key(rule_id: str) -> str:
    """rule_id -> 조치 맵 키. 명시 매핑 우선, 없으면 언어 접두를 떼고 접미 매칭."""
    if k := _EXPLICIT_KEY.get(rule_id):
        return k
    if rule_id.startswith("vendor."):
        return "secret"                     # 벤더 키·토큰은 전부 하드코딩된 비밀정보
    tail = rule_id.split(".")[-1]
    for k in REMEDIATION:
        if k in tail or k in rule_id:
            return k
    if rule_id.startswith("secret") or "secret" in rule_id:
        return "secret"
    if rule_id.startswith("pii"):
        return "pii"
    if "sql" in rule_id:
        return "sqli"
    return ""


def remediation_for(rule_id: str, en: bool = False) -> dict | None:
    """규칙 하나의 조치 정보. 매핑이 없으면 None(일반 문구로 떨어뜨릴지는 호출부 판단).

    MCP `explain` 이 쓰는 진입점이다 — reportlab 없이 규칙 id 하나로 제목·설명·조치·
    안전 예시·취약 예시를 얻는다.
    """
    key = rule_key(rule_id)
    if not key:
        return None
    table = REMEDIATION_EN if en else REMEDIATION
    title, desc, fix, safe = table.get(key, DEFAULT_REM_EN if en else _DEFAULT_REM)
    return {
        "key": key,
        "title": title,
        "description": desc,
        "remediation": fix,
        "safe_example": safe,
        "vulnerable_example": VULN_EXAMPLE.get(key),
    }
