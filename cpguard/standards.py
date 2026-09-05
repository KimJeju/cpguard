"""점검 기준(레퍼런스) — 어떤 기준으로 소스코드를 점검할지 고르는 축.

같은 탐지 결과라도 발주처가 요구하는 기준이 다르다. 공공 사업은 행정안전부
소프트웨어 개발보안 가이드의 점검항목으로, 민간·해외는 OWASP Top 10 이나 CWE 로
보고해야 한다. 그래서 **스캔은 한 번만 하고 기준은 볼 때 고른다** — 기준을 바꾸려고
다시 스캔할 이유가 없다.

연결 고리는 CWE 다. 규칙마다 CWE 가 붙어 있으므로 기준별 표는 "점검항목 -> CWE 목록"
하나면 되고, 판정은 탐지의 CWE 를 그 표에 대보는 것으로 끝난다.

항목 번호는 쓰지 않는다. 기준 문서는 판마다 번호와 개수가 달라, 번호를 실으면 계약서가
지정한 판과 대조하는 부담이 생긴다. 실제 진단 산출물도 번호가 아니라
**분류(기준) / 유형 / 보안약점명** 으로 적는다 — 그 관례를 그대로 따른다. 공식 코드가
있는 기준(OWASP A01~A10, CWE-89)만 코드를 함께 보여준다(show_code).
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    """점검항목 하나."""
    code: str                  # 필터·API 키 (표시용 공식 번호가 아니다 — Standard.show_code 참조)
    name: str                  # 항목명 (한국어)
    name_en: str
    group: str                 # 상위 분류
    group_en: str
    cwes: tuple[str, ...]      # 이 항목에 해당하는 CWE


@dataclass(frozen=True)
class Standard:
    id: str
    name: str
    name_en: str
    source: str                # 근거 문서 (한국어)
    items: tuple[Item, ...]
    source_en: str = ""        # 근거 문서 영문 표기(비면 source)
    show_code: bool = True     # code 가 그 기준의 공식 코드인가(OWASP A01·CWE-89 = 참)

    def source_for(self, lang: str) -> str:
        """근거 문서 표기. EN 보고서에 한국어 근거가 그대로 실리지 않게 한다."""
        return (self.source_en or self.source) if lang == "en" else self.source

    def item_for(self, cwe: str) -> Item | None:
        cwe = (cwe or "").strip().upper()
        if not cwe:
            return None
        for it in self.items:
            if cwe in it.cwes:
                return it
        return None

    @property
    def cwes(self) -> frozenset[str]:
        return frozenset(c for it in self.items for c in it.cwes)


def _mois() -> tuple[Item, ...]:
    """행정안전부 소프트웨어 개발보안 가이드 점검항목."""
    G = [
        ("입력데이터 검증 및 표현", "Input data validation and representation", [
            ("sql-injection", "SQL 삽입", "SQL injection", ("CWE-89",)),
            ("code-injection", "코드 삽입", "Code injection", ("CWE-94", "CWE-95", "CWE-96", "CWE-502")),
            ("path-resource-injection", "경로 조작 및 자원 삽입", "Path manipulation and resource injection",
             ("CWE-22", "CWE-23", "CWE-73", "CWE-99", "CWE-98")),
            ("xss", "크로스사이트 스크립트", "Cross-site scripting", ("CWE-79", "CWE-80")),
            ("os-command-injection", "운영체제 명령어 삽입", "OS command injection", ("CWE-78", "CWE-77")),
            ("file-upload", "위험한 형식 파일 업로드", "Unrestricted file upload", ("CWE-434",)),
            ("open-redirect", "신뢰되지 않는 URL 주소로 자동접속 연결", "Open redirect", ("CWE-601",)),
            ("xxe", "부적절한 XML 외부 개체 참조", "XML external entity (XXE)", ("CWE-611",)),
            ("xml-injection", "XML 삽입", "XML injection", ("CWE-91", "CWE-643", "CWE-652")),
            ("ldap-injection", "LDAP 삽입", "LDAP injection", ("CWE-90",)),
            ("csrf", "크로스사이트 요청 위조", "Cross-site request forgery", ("CWE-352",)),
            ("ssrf", "서버사이드 요청 위조", "Server-side request forgery", ("CWE-918",)),
            ("http-response-splitting", "HTTP 응답분할", "HTTP response splitting", ("CWE-113",)),
            ("integer-overflow", "정수형 오버플로", "Integer overflow", ("CWE-190", "CWE-191")),
            ("untrusted-security-decision", "보안기능 결정에 사용되는 부적절한 입력값",
             "Untrusted input in a security decision", ("CWE-807", "CWE-350")),
            ("buffer-overflow", "메모리 버퍼 오버플로", "Memory buffer overflow",
             ("CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-121", "CWE-122")),
            ("format-string", "포맷 스트링 삽입", "Format string injection", ("CWE-134",)),
        ]),
        ("보안기능", "Security features", [
            ("missing-authentication", "적절한 인증 없는 중요기능 허용",
             "Critical function without authentication", ("CWE-306",)),
            ("improper-authorization", "부적절한 인가", "Improper authorization", ("CWE-285", "CWE-862", "CWE-863")),
            ("wrong-permission", "중요한 자원에 대한 잘못된 권한 설정",
             "Incorrect permission assignment for a critical resource", ("CWE-732",)),
            ("weak-crypto-algorithm", "취약한 암호화 알고리즘 사용", "Use of a broken cryptographic algorithm",
             ("CWE-327", "CWE-328")),
            ("unencrypted-sensitive-data", "암호화되지 않은 중요정보", "Sensitive data without encryption",
             ("CWE-311", "CWE-312", "CWE-319", "CWE-359", "CWE-200")),
            ("hardcoded-secret", "하드코드된 중요정보", "Hard-coded credentials",
             ("CWE-798", "CWE-259", "CWE-321", "CWE-547")),
            ("short-key-length", "충분하지 않은 키 길이 사용", "Inadequate encryption key length", ("CWE-326",)),
            ("weak-random", "적절하지 않은 난수값 사용", "Use of insufficiently random values",
             ("CWE-330", "CWE-338", "CWE-337")),
            ("weak-password", "취약한 비밀번호 허용", "Weak password requirements", ("CWE-521", "CWE-522")),
            ("signature-verification", "부적절한 전자서명 확인", "Improper verification of a digital signature",
             ("CWE-347",)),
            ("certificate-validation", "부적절한 인증서 유효성 검증", "Improper certificate validation",
             ("CWE-295", "CWE-297")),
            ("persistent-cookie-exposure", "사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출",
             "Information exposure through persistent cookies", ("CWE-539", "CWE-1004")),
            ("sensitive-comment", "주석문 안에 포함된 시스템 주요정보",
             "Sensitive information in comments", ("CWE-615", "CWE-546")),
            ("hash-without-salt", "솔트 없이 일방향 해시함수 사용", "One-way hash without a salt",
             ("CWE-759", "CWE-760", "CWE-916")),
            ("code-download-without-integrity", "무결성 검사 없는 코드 다운로드",
             "Download of code without integrity check", ("CWE-494", "CWE-1392")),
            ("no-login-throttling", "반복된 인증시도 제한 기능 부재",
             "Improper restriction of excessive authentication attempts", ("CWE-307",)),
        ]),
        ("시간 및 상태", "Time and state", [
            ("toctou", "경쟁조건: 검사시점과 사용시점(TOCTOU)", "Race condition (TOCTOU)",
             ("CWE-367", "CWE-362")),
            ("infinite-loop", "종료되지 않는 반복문 또는 재귀함수", "Infinite loop or recursion",
             ("CWE-835", "CWE-674")),
        ]),
        ("에러처리", "Error handling", [
            ("error-message-exposure", "오류 메시지 정보노출", "Information exposure through an error message",
             ("CWE-209", "CWE-532")),
            ("missing-error-handling", "오류 상황 대응 부재", "Missing error handling", ("CWE-390", "CWE-391")),
            ("improper-exception-handling", "부적절한 예외 처리", "Improper exception handling", ("CWE-248", "CWE-754")),
        ]),
        ("코드오류", "Code error", [
            ("null-dereference", "Null Pointer 역참조", "NULL pointer dereference", ("CWE-476",)),
            ("resource-leak", "부적절한 자원 해제", "Improper resource release", ("CWE-404", "CWE-772")),
            ("use-after-free", "해제된 자원 사용", "Use after free", ("CWE-416",)),
            ("uninitialized-variable", "초기화되지 않은 변수 사용", "Use of an uninitialized variable", ("CWE-457",)),
        ]),
        ("캡슐화", "Encapsulation", [
            ("wrong-session-exposure", "잘못된 세션에 의한 데이터 정보 노출",
             "Data exposure through a wrong session", ("CWE-488",)),
            ("leftover-debug-code", "제거되지 않고 남은 디버그 코드", "Leftover debug code",
             ("CWE-489", "CWE-749")),
            ("private-array-returned", "Public 메소드로부터 반환된 Private 배열",
             "Private array returned from a public method", ("CWE-495",)),
            ("public-data-to-private-array", "Private 배열에 Public 데이터 할당",
             "Public data assigned to a private array", ("CWE-496",)),
        ]),
        ("API 오용", "API abuse", [
            ("dns-based-security-decision", "DNS lookup에 의존한 보안결정", "Security decision based on a DNS lookup",
             ("CWE-247", "CWE-292", "CWE-350")),
            ("dangerous-api", "취약한 API 사용", "Use of an inherently dangerous API",
             ("CWE-676", "CWE-242", "CWE-114", "CWE-926")),
        ]),
    ]
    return tuple(Item(code, name, name_en, g, g_en, cwes)
                 for g, g_en, rows in G for code, name, name_en, cwes in rows)


def _owasp() -> tuple[Item, ...]:
    """OWASP Top 10 (2021). 각 범주의 대표 CWE 매핑."""
    G = "OWASP Top 10 2021"
    rows = [
        ("A01", "취약한 접근 통제", "Broken Access Control",
         ("CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201", "CWE-275", "CWE-276",
          "CWE-284", "CWE-285", "CWE-352", "CWE-359", "CWE-377", "CWE-425", "CWE-497",
          "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-601", "CWE-639", "CWE-668",
          "CWE-706", "CWE-732", "CWE-862", "CWE-863", "CWE-913", "CWE-922", "CWE-98")),
        ("A02", "암호화 실패", "Cryptographic Failures",
         ("CWE-259", "CWE-261", "CWE-296", "CWE-310", "CWE-311", "CWE-312", "CWE-319",
          "CWE-321", "CWE-322", "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327",
          "CWE-328", "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337",
          "CWE-338", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757", "CWE-759",
          "CWE-760", "CWE-780", "CWE-818", "CWE-916")),
        ("A03", "인젝션", "Injection",
         ("CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79", "CWE-80", "CWE-83",
          "CWE-87", "CWE-88", "CWE-89", "CWE-90", "CWE-91", "CWE-93", "CWE-94", "CWE-95",
          "CWE-96", "CWE-97", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-134",
          "CWE-138", "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643",
          "CWE-644", "CWE-652", "CWE-917")),
        ("A04", "안전하지 않은 설계", "Insecure Design",
         ("CWE-73", "CWE-209", "CWE-256", "CWE-266", "CWE-269", "CWE-280", "CWE-311",
          "CWE-434", "CWE-501", "CWE-522", "CWE-525", "CWE-539", "CWE-579", "CWE-598",
          "CWE-602", "CWE-642", "CWE-646", "CWE-650", "CWE-653", "CWE-656", "CWE-657",
          "CWE-799", "CWE-807", "CWE-840", "CWE-841", "CWE-927", "CWE-1021", "CWE-1173")),
        ("A05", "보안 설정 오류", "Security Misconfiguration",
         ("CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260", "CWE-315", "CWE-266",
          "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547", "CWE-611", "CWE-614",
          "CWE-756", "CWE-776", "CWE-942", "CWE-1004", "CWE-1032", "CWE-1174", "CWE-489",
          "CWE-546", "CWE-615", "CWE-749")),
        ("A06", "취약하고 오래된 요소", "Vulnerable and Outdated Components",
         ("CWE-937", "CWE-1035", "CWE-1104", "CWE-1352")),
        ("A07", "식별 및 인증 실패", "Identification and Authentication Failures",
         ("CWE-255", "CWE-287", "CWE-288", "CWE-290", "CWE-294", "CWE-295", "CWE-297",
          "CWE-300", "CWE-302", "CWE-304", "CWE-306", "CWE-307", "CWE-346", "CWE-384",
          "CWE-521", "CWE-613", "CWE-620", "CWE-640", "CWE-798", "CWE-940", "CWE-1216")),
        ("A08", "소프트웨어 및 데이터 무결성 실패", "Software and Data Integrity Failures",
         ("CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565", "CWE-784",
          "CWE-829", "CWE-830", "CWE-915", "CWE-1392")),
        ("A09", "보안 로깅 및 모니터링 실패", "Security Logging and Monitoring Failures",
         ("CWE-117", "CWE-223", "CWE-532", "CWE-778")),
        ("A10", "서버측 요청 위조", "Server-Side Request Forgery", ("CWE-918",)),
    ]
    return tuple(Item(code, name, name_en, G, G, cwes) for code, name, name_en, cwes in rows)


def _efs() -> tuple[Item, ...]:
    """전자금융감독규정 기반 웹 취약점 점검항목.

    금융권 소스코드 진단 산출물은 행안부 보안약점과 별개로 전자금융감독규정 축을 함께
    싣는다. 여기 표는 그 축에서 참조하는 웹 취약점 항목(KISA 「홈페이지 취약점 진단·제거
    가이드」 28개 항목)이다. 설정·운영 영역 항목(디렉터리 인덱싱·관리자 페이지 노출 등)은
    소스코드 정적 분석의 대상이 아니므로 CWE 를 비워 두고 '진단 대상 아님'으로 표기한다.
    """
    G, GE = "웹 취약점", "Web vulnerabilities"
    rows = [
        ("buffer-overflow", "버퍼 오버플로우", "Buffer overflow",
         ("CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787")),
        ("format-string", "포맷 스트링", "Format string", ("CWE-134",)),
        ("ldap-injection", "LDAP 인젝션", "LDAP injection", ("CWE-90",)),
        ("os-command", "운영체제 명령 실행", "OS command execution", ("CWE-78", "CWE-77")),
        ("sql-injection", "SQL 인젝션", "SQL injection", ("CWE-89",)),
        ("ssi-injection", "SSI 인젝션", "SSI injection", ("CWE-97",)),
        ("xpath-injection", "XPath 인젝션", "XPath injection", ("CWE-643", "CWE-91", "CWE-652")),
        ("directory-indexing", "디렉터리 인덱싱", "Directory indexing", ()),
        ("information-leak", "정보 누출", "Information leakage",
         ("CWE-200", "CWE-209", "CWE-532", "CWE-546", "CWE-615", "CWE-359")),
        ("malicious-content", "악성 콘텐츠", "Malicious content", ("CWE-94", "CWE-98")),
        ("xss", "크로스사이트 스크립팅", "Cross-site scripting", ("CWE-79", "CWE-80")),
        ("weak-password-policy", "약한 문자열 강도", "Weak password strength",
         ("CWE-521", "CWE-522")),
        ("insufficient-authentication", "불충분한 인증", "Insufficient authentication",
         ("CWE-287", "CWE-306", "CWE-798", "CWE-259", "CWE-1392")),
        ("weak-password-recovery", "취약한 패스워드 복구", "Weak password recovery", ("CWE-640",)),
        ("csrf", "크로스사이트 리퀘스트 변조", "Cross-site request forgery", ("CWE-352",)),
        ("session-prediction", "세션 예측", "Session prediction",
         ("CWE-330", "CWE-338", "CWE-340", "CWE-337")),
        ("insufficient-authorization", "불충분한 인가", "Insufficient authorization",
         ("CWE-285", "CWE-862", "CWE-863", "CWE-732")),
        ("insufficient-session-expiration", "불충분한 세션 만료",
         "Insufficient session expiration", ("CWE-613",)),
        ("session-fixation", "세션 고정", "Session fixation", ("CWE-384",)),
        ("automation-attack", "자동화 공격", "Automation attack", ("CWE-307", "CWE-799")),
        ("missing-process-validation", "프로세스 검증 누락", "Missing process validation",
         ("CWE-840", "CWE-841")),
        ("file-upload", "파일 업로드", "File upload", ("CWE-434",)),
        ("file-download", "파일 다운로드", "File download", ("CWE-73",)),
        ("admin-page-exposure", "관리자 페이지 노출", "Admin page exposure", ()),
        ("path-traversal", "경로 추적", "Path traversal", ("CWE-22", "CWE-23", "CWE-99")),
        ("location-disclosure", "위치 공개", "Location disclosure", ("CWE-527", "CWE-538", "CWE-540")),
        ("cleartext-transmission", "데이터 평문 전송", "Cleartext transmission",
         ("CWE-319", "CWE-311", "CWE-312", "CWE-295", "CWE-321", "CWE-326", "CWE-327")),
        ("cookie-tampering", "쿠키 변조", "Cookie tampering",
         ("CWE-565", "CWE-614", "CWE-784", "CWE-1004", "CWE-539")),
    ]
    return tuple(Item(code, ko, en, G, GE, cwes) for code, ko, en, cwes in rows)


# CWE 기준으로 볼 때 쓰는 이름표. 우리 규칙이 실제로 내보내는 CWE 를 덮는다.
CWE_NAMES = {
    "CWE-22": ("경로 순회", "Path Traversal"),
    "CWE-78": ("운영체제 명령어 삽입", "OS Command Injection"),
    "CWE-79": ("크로스사이트 스크립트", "Cross-site Scripting"),
    "CWE-89": ("SQL 삽입", "SQL Injection"),
    "CWE-90": ("LDAP 삽입", "LDAP Injection"),
    "CWE-94": ("코드 삽입", "Code Injection"),
    "CWE-98": ("원격 파일 인클루전", "PHP Remote File Inclusion"),
    "CWE-114": ("프로세스 제어", "Process Control"),
    "CWE-120": ("버퍼 복사 시 크기 미검사", "Buffer Copy without Checking Size"),
    "CWE-134": ("포맷 스트링", "Use of Externally-Controlled Format String"),
    "CWE-200": ("민감정보 노출", "Exposure of Sensitive Information"),
    "CWE-295": ("부적절한 인증서 검증", "Improper Certificate Validation"),
    "CWE-321": ("하드코드된 암호화 키", "Use of Hard-coded Cryptographic Key"),
    "CWE-327": ("취약한 암호화 알고리즘", "Use of a Broken Cryptographic Algorithm"),
    "CWE-338": ("암호학적으로 취약한 난수", "Cryptographically Weak PRNG"),
    "CWE-359": ("개인정보 노출", "Exposure of Private Personal Information"),
    "CWE-489": ("제거되지 않은 디버그 코드", "Active Debug Code"),
    "CWE-502": ("신뢰할 수 없는 데이터 역직렬화", "Deserialization of Untrusted Data"),
    "CWE-522": ("불충분하게 보호된 자격증명", "Insufficiently Protected Credentials"),
    "CWE-546": ("의심스러운 주석", "Suspicious Comment"),
    "CWE-601": ("열린 리다이렉트", "Open Redirect"),
    "CWE-611": ("XML 외부 개체 참조", "XML External Entity Reference"),
    "CWE-615": ("주석 내 정보 노출", "Information Exposure Through Comments"),
    "CWE-643": ("XPath 삽입", "XPath Injection"),
    "CWE-749": ("노출된 위험 메서드", "Exposed Dangerous Method or Function"),
    "CWE-798": ("하드코드된 자격증명", "Use of Hard-coded Credentials"),
    "CWE-918": ("서버측 요청 위조", "Server-Side Request Forgery"),
    "CWE-926": ("안드로이드 컴포넌트 부적절 익스포트", "Improper Export of Android Components"),
    "CWE-1004": ("HttpOnly 없는 민감 쿠키", "Sensitive Cookie Without HttpOnly"),
    "CWE-1392": ("기본 자격증명 사용", "Use of Default Credentials"),
}


def _cwe_items() -> tuple[Item, ...]:
    G = "CWE"
    return tuple(Item(c, ko, en, G, G, (c,))
                 for c, (ko, en) in sorted(CWE_NAMES.items(),
                                           key=lambda kv: int(kv[0].split("-")[1])))


STANDARDS: dict[str, Standard] = {
    "mois": Standard("mois", "행정안전부 소프트웨어 개발보안 가이드",
                     "MOIS Secure Coding Guide (Korea)",
                     "행정안전부 「소프트웨어 개발보안 가이드」 보안약점", _mois(),
                     source_en="MOIS Software Development Security Guide (Korea)",
                     show_code=False),
    "efs": Standard("efs", "전자금융감독규정 웹 취약점", "Electronic Financial Supervision (Korea)",
                    "전자금융감독규정 · KISA 「홈페이지 취약점 진단·제거 가이드」 점검항목",
                    _efs(),
                    source_en=("Electronic Financial Supervision Regulation · KISA web "
                               "vulnerability assessment checklist (Korea)"),
                    show_code=False),
    "owasp": Standard("owasp", "OWASP Top 10 (2021)", "OWASP Top 10 (2021)",
                      "OWASP Top 10:2021", _owasp()),
    "cwe": Standard("cwe", "CWE", "CWE", "MITRE Common Weakness Enumeration", _cwe_items()),
}

DEFAULT = "mois"


def get(std_id: str | None) -> Standard | None:
    """기준 id -> Standard. 없거나 모르는 값이면 None(= 기준 미적용)."""
    return STANDARDS.get((std_id or "").strip().lower()) or None


def rule_cwes() -> frozenset[str]:
    """현재 룰셋이 실제로 탐지할 수 있는 CWE 집합.

    이걸 봐야 '탐지 0건'과 '애초에 점검하지 않음'을 구분할 수 있다. 규칙이 없는 항목을
    양호로 찍으면 안 한 점검을 했다고 쓰는 셈이라, 산출물의 신뢰가 거기서 무너진다."""
    cached = getattr(rule_cwes, "_c", None)
    if cached is not None:
        return cached
    from .patterns import load_pattern_rules
    from .taint.spec import load_rules
    out = frozenset(c for c in ({r.cwe for r in load_rules()}
                                | {r.cwe for r in load_pattern_rules()}) if c)
    rule_cwes._c = out
    return out


# 점검항목 판정
VIOLATED = "violated"       # 탐지됨
PASS = "pass"               # 점검했고 탐지 없음
NOT_COVERED = "not_covered"  # 이 항목을 볼 수 있는 규칙이 없음 = 점검하지 않음

VERDICT_KO = {VIOLATED: "취약", PASS: "양호", NOT_COVERED: "진단 대상 아님"}
VERDICT_EN = {VIOLATED: "Violated", PASS: "Pass", NOT_COVERED: "Not assessed"}


def coverage(std: Standard, cwe_counts: dict[str, int],
             available: frozenset[str] | None = None) -> list[dict]:
    """점검항목별 결과. 산출물의 '점검항목 표'가 이 모양 그대로 들어간다.

    cwe_counts: CWE -> 탐지 건수.
    available: 룰셋이 탐지 가능한 CWE(기본 rule_cwes()). 항목의 CWE 중 하나도 다루지
      못하면 양호가 아니라 '진단 대상 아님'이다 — 설정·운영 영역 항목(디렉터리 인덱싱 등)이
      정적 분석으로 확인되지 않았다는 사실을 산출물에 그대로 남긴다.
    """
    if available is None:
        available = rule_cwes()
    out = []
    for it in std.items:
        n = sum(cwe_counts.get(c, 0) for c in it.cwes)
        covered = any(c in available for c in it.cwes)
        out.append({"code": it.code, "name": it.name, "name_en": it.name_en,
                    "group": it.group, "group_en": it.group_en, "n": n,
                    "covered": covered, "cwes": list(it.cwes),
                    "verdict": VIOLATED if n else (PASS if covered else NOT_COVERED)})
    return out


def unmapped(std: Standard, cwe_counts: dict[str, int]) -> dict[str, int]:
    """이 기준의 어느 항목에도 걸리지 않은 탐지. 숨기지 않고 따로 보고한다."""
    known = std.cwes
    return {c: n for c, n in cwe_counts.items() if c and c not in known}
