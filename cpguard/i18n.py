"""서버측 로컬라이즈 — 룰 메시지·PDF 산출물 영문화.

UI(웹) 는 base.html 의 클라이언트 사전으로 번역하지만, 아래 두 부류는 서버에서
생성되므로(스캔 시 DB 에 KO 로 저장된 룰 메시지, reportlab PDF 문서) 서버에서 번역한다.

- `tr(text, lang)` : 저장된 KO 문자열 → EN (맵에 있으면). lang!='en' 이면 원문 그대로.
- `SEV_EN` / `REMEDIATION_EN` : PDF 조치 가이드용 영문 테이블.

언어는 뷰가 쿠키(cpguard_lang)/`?lang=` 로 판별해 넘긴다. 분석목록표(xlsx)·SARIF 는
한글 고객제출 규격·기계 수집용이라 대상에서 제외한다.
"""
from __future__ import annotations

# ── 룰 메시지 (specs/*.yml · patterns/*.yml · patterns.py 인라인) ──────────────
MSG: dict[str, str] = {
    "ADO/OLEDB 연결 문자열이 하드코딩되어 있습니다.": "An ADO/OLEDB connection string is hardcoded.",
    "AWS Access Key ID 가 하드코딩되어 있습니다.": "An AWS Access Key ID is hardcoded.",
    "AWS Secret Access Key 로 보이는 값이 하드코딩되어 있습니다.": "A value that looks like an AWS Secret Access Key is hardcoded.",
    "Authorization 헤더 값이 하드코딩되어 있습니다.": "An Authorization header value is hardcoded.",
    "Azure SAS 토큰이 하드코딩되어 있습니다.": "An Azure SAS token is hardcoded.",
    "Azure Storage 계정 키가 하드코딩되어 있습니다.": "An Azure Storage account key is hardcoded.",
    "Firebase 서버 키가 하드코딩되어 있습니다.": "A Firebase server key is hardcoded.",
    "GCP 서비스 계정 키 파일(JSON)이 포함되어 있습니다.": "A GCP service-account key file (JSON) is included.",
    "GitHub 토큰이 하드코딩되어 있습니다.": "A GitHub token is hardcoded.",
    "GitLab 토큰이 하드코딩되어 있습니다.": "A GitLab token is hardcoded.",
    "Google API 키가 하드코딩되어 있습니다.": "A Google API key is hardcoded.",
    "Google OAuth 클라이언트 ID 가 하드코딩되어 있습니다.": "A Google OAuth client ID is hardcoded.",
    "JDBC 접속 문자열이 하드코딩되어 있습니다.": "A JDBC connection string is hardcoded.",
    "Mailgun/Mailchimp 키가 하드코딩되어 있습니다.": "A Mailgun/Mailchimp key is hardcoded.",
    "OpenAI/Anthropic API 키가 하드코딩되어 있습니다.": "An OpenAI/Anthropic API key is hardcoded.",
    "Oracle TNS/SID 접속 정보가 하드코딩되어 있습니다.": "Oracle TNS/SID connection info is hardcoded.",
    "SMTP/LDAP 바인딩 계정 설정이 소스에 있습니다.": "SMTP/LDAP bind-account settings are present in the source.",
    "SQL 문자열을 결합해 만들고 있습니다 — 파라미터 바인딩을 권장합니다.": "A SQL string is built by concatenation — use parameter binding.",
    "SendGrid 키가 하드코딩되어 있습니다.": "A SendGrid key is hardcoded.",
    "Slack 토큰/웹훅이 하드코딩되어 있습니다.": "A Slack token/webhook is hardcoded.",
    "Stripe 키가 하드코딩되어 있습니다.": "A Stripe key is hardcoded.",
    "TLS 인증서 검증이 비활성화되어 있습니다 (중간자 공격 노출).": "TLS certificate verification is disabled (exposed to man-in-the-middle).",
    "Twilio SID/키가 하드코딩되어 있습니다.": "A Twilio SID/key is hardcoded.",
    "URI 안에 계정:비밀번호가 하드코딩되어 있습니다.": "A user:password credential is hardcoded inside a URI.",
    "WebView 에 위험한 설정(파일 접근·JS 인터페이스)이 켜져 있습니다.": "Dangerous WebView settings (file access · JS interface) are enabled.",
    "dangerouslySetInnerHTML 사용 — 정제되지 않은 값이면 XSS 가 됩니다.": "dangerouslySetInnerHTML is used — unsanitized input leads to XSS.",
    "document.write 사용 — DOM 기반 XSS 위험이 있습니다.": "document.write is used — risk of DOM-based XSS.",
    "innerHTML/outerHTML 에 직접 대입 — 정제되지 않은 값이면 XSS 가 됩니다.": "Direct assignment to innerHTML/outerHTML — unsanitized input leads to XSS.",
    "npm 토큰이 하드코딩되어 있습니다.": "An npm token is hardcoded.",
    "개발자 로컬 경로가 소스에 남아 있습니다 (사용자명·내부 구조 노출).": "A developer's local path remains in the source (leaks username · internal structure).",
    "개인정보를 담는 것으로 보이는 컬럼/식별자입니다 — 저장·암호화 정책을 확인하세요.": "A column/identifier that appears to hold personal data — review storage/encryption policy.",
    "개인키(PEM/PGP/PuTTY)가 소스에 포함되어 있습니다.": "A private key (PEM/PGP/PuTTY) is included in the source.",
    "관리자 경로가 하드코딩되어 있습니다.": "An admin path is hardcoded.",
    "국내 PG(이니시스/토스/아임포트 등) 결제 키 설정이 하드코딩되어 있습니다.": "A domestic PG (Inicis/Toss/Iamport, etc.) payment key is hardcoded.",
    "기본/테스트 계정 조합(admin/admin 등)이 소스에 있습니다.": "A default/test account pair (e.g. admin/admin) is present in the source.",
    "디버그 모드가 켜져 있습니다 — 운영 환경에서 정보가 노출됩니다.": "Debug mode is enabled — leaks information in production.",
    "명령 실행 API 사용 — 인자가 외부 입력이면 명령 주입이 됩니다 (흐름 분석 결과와 대조).": "A command-execution API is used — if its argument is external input this is command injection (cross-check with the data-flow result).",
    "보안 용도에 예측 가능한 난수를 사용하고 있습니다.": "A predictable RNG is used for a security purpose.",
    "비밀번호/토큰/키가 문자열로 하드코딩되어 있습니다.": "A password/token/key is hardcoded as a string.",
    "사설 IP 주소가 소스에 하드코딩되어 있습니다 (내부망 구조 노출).": "A private IP address is hardcoded in the source (leaks internal network structure).",
    "사업자등록번호 형식의 값이 소스에 있습니다 (개인정보는 아니나 참고).": "A value in business-registration-number format is present (not PII, but noted).",
    "사용자 입력이 SQL 질의문으로 흘러 들어갑니다 (SQL 주입).": "User input flows into a SQL query (SQL injection).",
    "사용자 입력이 리다이렉트 위치로 흘러 들어갑니다 (오픈 리다이렉트).": "User input flows into a redirect target (open redirect).",
    "사용자 입력이 명령 실행 함수로 흘러 들어갑니다 (명령 주입).": "User input flows into a command-execution function (command injection).",
    "사용자 입력이 시스템 명령 실행으로 흘러 들어갑니다 (명령 주입).": "User input flows into system command execution (command injection).",
    "사용자 입력이 외부 요청 URL로 흘러 들어갑니다 (SSRF).": "User input flows into an outbound request URL (SSRF).",
    "사용자 입력이 외부 요청 대상으로 흘러 들어갑니다 (SSRF).": "User input flows into an outbound request target (SSRF).",
    "사용자 입력이 정제 없이 HTML 응답으로 흘러 들어갑니다 (XSS).": "User input flows unsanitized into an HTML response (XSS).",
    "사용자 입력이 정제 없이 HTML 출력으로 흘러 들어갑니다 (XSS).": "User input flows unsanitized into HTML output (XSS).",
    "사용자 입력이 정제 없이 출력됩니다 (XSS).": "User input is output without sanitization (XSS).",
    "사용자 입력이 코드 실행 함수로 흘러 들어갑니다 (코드 주입).": "User input flows into a code-execution function (code injection).",
    "사용자 입력이 파일 경로로 흘러 들어갑니다 (경로 조작).": "User input flows into a file path (path traversal).",
    "사용자 입력이 파일 포함/경로로 흘러 들어갑니다 (LFI/RFI·경로 조작).": "User input flows into a file include/path (LFI/RFI · path traversal).",
    "서명이 포함된 JWT 가 소스에 들어 있습니다.": "A signed JWT is present in the source.",
    "설정 파일에 자격증명이 평문으로 들어 있습니다.": "Credentials are stored in plaintext in a config file.",
    "신용카드번호로 확인된 값이 소스에 있습니다 (Luhn 검증 통과).": "A value confirmed as a credit-card number is present (passes Luhn check).",
    "여권번호 형식의 값이 소스에 있습니다.": "A value in passport-number format is present in the source.",
    "연결 문자열에 비밀번호가 평문으로 들어 있습니다.": "A connection string contains a plaintext password.",
    "유선전화번호 형식의 값이 소스에 있습니다.": "A value in landline phone-number format is present.",
    "이메일 주소가 소스에 있습니다.": "An email address is present in the source.",
    "인증 정보가 포함된 DB 접속 문자열이 하드코딩되어 있습니다.": "A DB connection string with credentials is hardcoded.",
    "인증 토큰을 localStorage/sessionStorage 에 저장 — XSS 시 탈취됩니다.": "An auth token is stored in localStorage/sessionStorage — stealable via XSS.",
    "임시/테스트용 표시가 남아 있습니다 — 운영 반영 전 정리 대상입니다.": "A temporary/test marker remains — clean up before production.",
    "제거되지 않은 디버그 코드가 남아 있습니다.": "Leftover debug code remains.",
    "주민등록번호/외국인등록번호로 확인된 값이 소스에 있습니다 (체크섬 검증 통과).": "A value confirmed as a resident/foreigner registration number is present (passes checksum).",
    "주석에 인증 정보로 보이는 값이 적혀 있습니다.": "A value that looks like a credential is written in a comment.",
    "취약한 암호 알고리즘(DES/RC4/ECB) 사용.": "A weak cipher algorithm (DES/RC4/ECB) is used.",
    "취약한 해시 알고리즘(MD5/SHA1) 사용 — 비밀번호·무결성 용도로 부적합합니다.": "A weak hash algorithm (MD5/SHA1) is used — unsuitable for passwords/integrity.",
    "카카오/네이버/NHN 클라우드 키 설정이 하드코딩되어 있습니다.": "A Kakao/Naver/NHN Cloud key is hardcoded.",
    "쿠키에 httpOnly/secure 플래그가 꺼져 있습니다.": "The cookie's httpOnly/secure flags are disabled.",
    "휴대폰번호 형식의 값이 소스에 있습니다.": "A value in mobile phone-number format is present.",
    "민감한 파일명/확장자입니다 — 저장소에 있으면 안 되는 파일일 수 있습니다.": "A sensitive filename/extension — this file probably should not be in the repository.",
    # 다국어 확장(Java·Kotlin·Go·Ruby·C/C++·Swift·C#) 신규 유형
    "사용자 입력이 역직렬화 함수로 흘러 들어갑니다 (안전하지 않은 역직렬화).": "User input flows into a deserialization function (insecure deserialization).",
    "사용자 입력이 길이 검사 없는 버퍼 복사 함수로 흘러 들어갑니다 (버퍼 오버플로).": "User input flows into an unbounded buffer-copy function (buffer overflow).",
    "사용자 입력이 포맷 문자열 인자로 흘러 들어갑니다 (포맷 스트링).": "User input flows into a format-string argument (format string vulnerability).",
    "사용자 입력이 LDAP 질의로 흘러 들어갑니다 (LDAP 주입).": "User input flows into an LDAP query (LDAP injection).",
    "사용자 입력이 XPath 질의로 흘러 들어갑니다 (XPath 주입).": "User input flows into an XPath query (XPath injection).",
    "사용자 입력이 WebView 로드/스크립트 실행으로 흘러 들어갑니다 (WebView XSS).": "User input flows into a WebView load / script execution (WebView XSS).",
    "사용자 입력이 Intent 실행으로 흘러 들어갑니다 (Intent 리다이렉션).": "User input flows into an Intent launch (Intent redirection).",
    "사용자 입력이 라이브러리 로드 경로로 흘러 들어갑니다 (라이브러리 주입).": "User input flows into a library load path (library injection).",
}

# ── PDF 문서 챔버(제목·표머리·라벨·정적 문단) ──────────────────────────────
PDF_UI: dict[str, str] = {
    "소스코드 취약점 진단 결과 보고서": "Source Code Vulnerability Assessment Report",
    "SAST 진단 · CPGuard": "SAST Assessment · CPGuard",
    "프로젝트": "Project", "대상": "Target", "분석 도구": "Analyzer",
    "CPGuard (CPG 기반 taint 분석)": "CPGuard (CPG-based taint analysis)",
    "분석 일시": "Scan time", "소스 파일 수": "Source files", "총 이슈": "Total issues",
    "작성일": "Date", "작성자": "Author",
    "1. 진단 개요": "1. Overview",
    "본 보고서는 CPGuard 정적 분석(데이터 흐름 taint + 패턴)을 통해 대상 소스코드의 "
    "보안약점을 도출한 결과이다. 각 이슈는 CWE·OWASP 로 분류되며, 유형별 조치 방법은 "
    "별도의 조치 가이드를 참조한다.":
        "This report presents the security weaknesses found in the target source code by "
        "CPGuard static analysis (data-flow taint + patterns). Each issue is classified by "
        "CWE and OWASP; per-type remediation is covered in the separate remediation guide.",
    "2. 위험도별 진단 결과": "2. Results by Severity",
    "3. 레퍼런스별(CWE) 집계": "3. Summary by Reference (CWE)",
    "규칙 예": "Example rule", "개수": "Count", "위험도": "Severity", "합계": "Total",
    "4. 상세 결과": "4. Detailed Findings",
    "위치": "Location", "조치": "Remediation", "5. 총평": "5. Summary",
    "진단 결과 보고서": "Assessment Report",
    # 조치 가이드
    "보안약점 조치 가이드": "Security Remediation Guide",
    "유형별 설명 · 조치 방법 · 안전 예시": "Per-type explanation · remediation · safe examples",
    "탐지 유형": "Types detected",
    "설명": "Explanation", "조치 방법": "Remediation", "안전 예시:": "Safe example:",
    "해당 위치": "Locations", "조치 가이드": "Remediation Guide",
    # 고도화 보고서 섹션
    "문서 개정 이력": "Document Revision History",
    "버전": "Version", "일자": "Date", "내용": "Description", "작성": "Author",
    "최초 작성": "Initial draft", "결과 반영·보완": "Findings incorporated / revised",
    "목차": "Contents",
    "1. 진단 개요": "1. Assessment Overview",
    "1.1 진단 배경 및 목적": "1.1 Background & Objective",
    "1.2 진단 대상 범위": "1.2 Assessment Scope",
    "1.3 진단 방법 및 기준": "1.3 Methodology & Criteria",
    "2. 진단 결과 요약": "2. Results Summary",
    "3. 진단 항목": "3. Checklist",
    "4. 상세 진단 결과": "4. Detailed Findings",
    "5. 종합 의견": "5. Overall Assessment",
    "부록 A. 위험도 판정 기준": "Appendix A. Severity Rating Criteria",
    "프로젝트": "Project", "대상 파일 수": "Source files", "탐지 이슈 수": "Total findings",
    "분석 언어": "Languages", "진단 도구": "Tool", "진단 기준": "Standards", "진단 일시": "Date",
    "대상": "Target", "항목": "Item", "값": "Value",
    "위험도 분포": "Severity Distribution", "취약점 유형(CWE) 상위": "Top Vulnerability Types (CWE)",
    "점검 항목": "Check item", "규칙": "Rule", "탐지": "Found",
    "취약점": "Vulnerability", "데이터 흐름": "Data Flow", "영향": "Impact",
    "조치 방안": "Remediation", "안전한 코드 예시": "Safe Code Example", "참고": "References",
    "판정": "Rating", "기준": "Criteria", "조치 우선순위": "Priority",
    "진단 이력": "Assessment History", "회차": "Run", "일시": "Date", "신규": "New", "해결": "Resolved",
    "총 진단 횟수": "Total runs", "이전 대비": "vs previous",
    "발주처/고객": "Client", "수행 기관/회사": "Assessed by", "진단 담당자": "Assessor",
    "진단 수행 기간": "Assessment period", "보고서 버전": "Report version",
    "CPGuard (CPG 기반 taint 분석 + 패턴)": "CPGuard (CPG-based taint analysis + patterns)",
    "본 보고서는 대상 소스코드에 대해 CPGuard 정적 분석(데이터 흐름 taint 분석 + 패턴 점검)을 "
    "수행하여 도출한 보안약점과 그 조치 방안을 기술한다. 각 취약점은 CWE·OWASP 기준으로 분류하고, "
    "위험도에 따라 조치 우선순위를 제시한다.":
        "This report describes the security weaknesses found in the target source code by CPGuard "
        "static analysis (data-flow taint analysis + pattern checks) and their remediation. Each "
        "weakness is classified by CWE and OWASP, with a remediation priority by severity.",
    "이번 진단에서 탐지된 점검 항목(규칙)과 분류·건수는 다음과 같다.":
        "The check items (rules) detected in this assessment, with their classification and counts, are listed below.",
    "즉시 조치": "Immediate", "우선 조치": "High priority", "계획 조치": "Planned",
    "참고 개선": "Advisory", "정보성": "Informational",
}

# 데이터 흐름 단계 라벨(SARIF kind)
STEP_LABEL = {"source": "입력(Source)", "sink": "위험지점(Sink)", "propagation": "전파(Propagation)",
              "sanitizer": "정제(Sanitizer)", "match": "탐지 지점"}
STEP_LABEL_EN = {"source": "Source", "sink": "Sink", "propagation": "Propagation",
                 "sanitizer": "Sanitizer", "match": "Match"}

SEV_EN = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low", "info": "Info"}

# 유형별 조치 권고(영문) — pdf.REMEDIATION 과 같은 키. (제목, 설명, 조치, 안전 예시)
REMEDIATION_EN = {
    "sqli": ("SQL Injection",
             "User input is concatenated into a SQL query without validation, letting an attacker alter the query structure.",
             "Use parameter binding (prepared statements / parameterized queries) instead of string concatenation. With an ORM, avoid raw query concatenation.",
             "db.query('SELECT * FROM users WHERE id = ?', [userId])"),
    "command-injection": ("OS Command Injection",
             "User input is passed to a shell command-execution function, allowing arbitrary commands to run.",
             "Instead of shell-based exec, pass the command and arguments separately to execFile/spawn, and validate input against an allowlist.",
             "child_process.execFile('convert', [inputPath, outputPath])"),
    "xss": ("Cross-Site Scripting (XSS)",
             "User input is written to the HTML response without escaping, allowing scripts to execute.",
             "Apply context-aware escaping (HTML/attribute/JS) on output and use the template engine's auto-escaping. Prefer textContent over innerHTML.",
             "el.textContent = userInput  // no innerHTML"),
    "path-traversal": ("Path Traversal",
             "User input is used in a file path, allowing parent-directory (../) access.",
             "Resolve against a base directory then check the prefix, and restrict filenames with an allowlist.",
             "p = path.resolve(base, name); if(!p.startsWith(base)) throw"),
    "ssrf": ("Server-Side Request Forgery (SSRF)",
             "The server sends a request to a user-supplied URL, exposing internal network resources.",
             "Restrict target hosts to an allowlist and block private/metadata addresses (169.254.169.254, etc.).",
             "if(!ALLOWED_HOSTS.has(new URL(url).host)) reject()"),
    "code-injection": ("Code Injection",
             "User input is passed to dynamic code execution such as eval, allowing arbitrary code to run.",
             "Remove eval/new Function/dynamic execution. Parse data with safe alternatives like JSON.parse.",
             "const data = JSON.parse(input)  // no eval"),
    "file-inclusion": ("File Inclusion",
             "User input is used in an include/require path, allowing arbitrary files to be included.",
             "Restrict dynamic include paths to an allowlist and never use user input directly as a path.",
             "$allowed = ['home','about']; include $allowed[$page] . '.php';"),
    "open-redirect": ("Open Redirect",
             "User input is used as a redirect target and can be abused for phishing.",
             "Restrict the redirect target to internal relative paths or an allowlist.",
             "if(!target.startsWith('/')) target = '/'"),
    "secret": ("Hardcoded Secret",
             "A password, API key, or token is hardcoded in the source, risking exposure.",
             "Move secrets to environment variables / a secret manager, and immediately revoke and rotate exposed keys.",
             "apiKey = process.env.API_KEY"),
    "pii": ("Personal Data Exposure (PII)",
             "Personal data such as national IDs, card numbers, or contacts is present in the source/config.",
             "Remove real data from the source and apply encryption/masking at rest.",
             "// reference env / secure store instead of real data"),
    "tls": ("TLS Verification Disabled",
            "Disabling certificate verification exposes the connection to man-in-the-middle attacks.",
            "Enable certificate verification and register any required internal CA in the trust store.",
            "verify=True  // rejectUnauthorized: true"),
    "crypto": ("Weak Cipher/Hash",
               "Use of a weak algorithm such as MD5/SHA-1/DES/ECB was found.",
               "Replace with strong algorithms (SHA-256+, AES-GCM) and hash passwords with bcrypt/argon2.",
               "hashlib.sha256(x)  // bcrypt for passwords"),
}
DEFAULT_REM_EN = ("Security Weakness", "The detected type needs remediation.",
                  "Apply input validation, output encoding, and least-privilege per the relevant CWE guidance.", "")

_T = {**MSG, **PDF_UI}


def tr(text, lang: str = "ko"):
    """저장된 KO 문자열을 EN 으로. lang!='en' 이거나 맵에 없으면 원문 그대로."""
    if lang != "en" or not text:
        return text
    return _T.get(text, text)
