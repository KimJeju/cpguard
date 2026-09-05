"""점검 기준(레퍼런스) — 어떤 기준으로 소스코드를 점검할지 고르는 축.

같은 탐지 결과라도 발주처가 요구하는 기준이 다르다. 공공 사업은 행정안전부
소프트웨어 개발보안 가이드의 점검항목으로, 민간·해외는 OWASP Top 10 이나 CWE 로
보고해야 한다. 그래서 **스캔은 한 번만 하고 기준은 볼 때 고른다** — 기준을 바꾸려고
다시 스캔할 이유가 없다.

연결 고리는 CWE 다. 규칙마다 CWE 가 붙어 있으므로 기준별 표는 "점검항목 -> CWE 목록"
하나면 되고, 판정은 탐지의 CWE 를 그 표에 대보는 것으로 끝난다.

주의: 기준 문서는 판마다 항목 번호와 개수가 조금씩 다르다. 여기 표는 CWE 매핑을
기준으로 하며, 계약서가 특정 판을 지정한다면 항목 번호는 그 판으로 대조해야 한다.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Item:
    """점검항목 하나."""
    code: str                  # 항목 코드
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
    source: str                # 근거 문서
    items: tuple[Item, ...]

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
            ("SC-01", "SQL 삽입", "SQL injection", ("CWE-89",)),
            ("SC-02", "코드 삽입", "Code injection", ("CWE-94", "CWE-95", "CWE-96", "CWE-502")),
            ("SC-03", "경로 조작 및 자원 삽입", "Path manipulation and resource injection",
             ("CWE-22", "CWE-23", "CWE-73", "CWE-99", "CWE-98")),
            ("SC-04", "크로스사이트 스크립트", "Cross-site scripting", ("CWE-79", "CWE-80")),
            ("SC-05", "운영체제 명령어 삽입", "OS command injection", ("CWE-78", "CWE-77")),
            ("SC-06", "위험한 형식 파일 업로드", "Unrestricted file upload", ("CWE-434",)),
            ("SC-07", "신뢰되지 않는 URL 주소로 자동접속 연결", "Open redirect", ("CWE-601",)),
            ("SC-08", "부적절한 XML 외부 개체 참조", "XML external entity (XXE)", ("CWE-611",)),
            ("SC-09", "XML 삽입", "XML injection", ("CWE-91", "CWE-643", "CWE-652")),
            ("SC-10", "LDAP 삽입", "LDAP injection", ("CWE-90",)),
            ("SC-11", "크로스사이트 요청 위조", "Cross-site request forgery", ("CWE-352",)),
            ("SC-12", "서버사이드 요청 위조", "Server-side request forgery", ("CWE-918",)),
            ("SC-13", "HTTP 응답분할", "HTTP response splitting", ("CWE-113",)),
            ("SC-14", "정수형 오버플로", "Integer overflow", ("CWE-190", "CWE-191")),
            ("SC-15", "보안기능 결정에 사용되는 부적절한 입력값",
             "Untrusted input in a security decision", ("CWE-807", "CWE-350")),
            ("SC-16", "메모리 버퍼 오버플로", "Memory buffer overflow",
             ("CWE-119", "CWE-120", "CWE-125", "CWE-787", "CWE-121", "CWE-122")),
            ("SC-17", "포맷 스트링 삽입", "Format string injection", ("CWE-134",)),
        ]),
        ("보안기능", "Security features", [
            ("SC-18", "적절한 인증 없는 중요기능 허용",
             "Critical function without authentication", ("CWE-306",)),
            ("SC-19", "부적절한 인가", "Improper authorization", ("CWE-285", "CWE-862", "CWE-863")),
            ("SC-20", "중요한 자원에 대한 잘못된 권한 설정",
             "Incorrect permission assignment for a critical resource", ("CWE-732",)),
            ("SC-21", "취약한 암호화 알고리즘 사용", "Use of a broken cryptographic algorithm",
             ("CWE-327", "CWE-328")),
            ("SC-22", "암호화되지 않은 중요정보", "Sensitive data without encryption",
             ("CWE-311", "CWE-312", "CWE-319", "CWE-359", "CWE-200")),
            ("SC-23", "하드코드된 중요정보", "Hard-coded credentials",
             ("CWE-798", "CWE-259", "CWE-321", "CWE-547")),
            ("SC-24", "충분하지 않은 키 길이 사용", "Inadequate encryption key length", ("CWE-326",)),
            ("SC-25", "적절하지 않은 난수값 사용", "Use of insufficiently random values",
             ("CWE-330", "CWE-338", "CWE-337")),
            ("SC-26", "취약한 비밀번호 허용", "Weak password requirements", ("CWE-521", "CWE-522")),
            ("SC-27", "부적절한 전자서명 확인", "Improper verification of a digital signature",
             ("CWE-347",)),
            ("SC-28", "부적절한 인증서 유효성 검증", "Improper certificate validation",
             ("CWE-295", "CWE-297")),
            ("SC-29", "사용자 하드디스크에 저장되는 쿠키를 통한 정보 노출",
             "Information exposure through persistent cookies", ("CWE-539", "CWE-1004")),
            ("SC-30", "주석문 안에 포함된 시스템 주요정보",
             "Sensitive information in comments", ("CWE-615", "CWE-546")),
            ("SC-31", "솔트 없이 일방향 해시함수 사용", "One-way hash without a salt",
             ("CWE-759", "CWE-760", "CWE-916")),
            ("SC-32", "무결성 검사 없는 코드 다운로드",
             "Download of code without integrity check", ("CWE-494", "CWE-1392")),
            ("SC-33", "반복된 인증시도 제한 기능 부재",
             "Improper restriction of excessive authentication attempts", ("CWE-307",)),
        ]),
        ("시간 및 상태", "Time and state", [
            ("SC-34", "경쟁조건: 검사시점과 사용시점(TOCTOU)", "Race condition (TOCTOU)",
             ("CWE-367", "CWE-362")),
            ("SC-35", "종료되지 않는 반복문 또는 재귀함수", "Infinite loop or recursion",
             ("CWE-835", "CWE-674")),
        ]),
        ("에러처리", "Error handling", [
            ("SC-36", "오류 메시지 정보노출", "Information exposure through an error message",
             ("CWE-209", "CWE-532")),
            ("SC-37", "오류 상황 대응 부재", "Missing error handling", ("CWE-390", "CWE-391")),
            ("SC-38", "부적절한 예외 처리", "Improper exception handling", ("CWE-248", "CWE-754")),
        ]),
        ("코드오류", "Code error", [
            ("SC-39", "Null Pointer 역참조", "NULL pointer dereference", ("CWE-476",)),
            ("SC-40", "부적절한 자원 해제", "Improper resource release", ("CWE-404", "CWE-772")),
            ("SC-41", "해제된 자원 사용", "Use after free", ("CWE-416",)),
            ("SC-42", "초기화되지 않은 변수 사용", "Use of an uninitialized variable", ("CWE-457",)),
        ]),
        ("캡슐화", "Encapsulation", [
            ("SC-43", "잘못된 세션에 의한 데이터 정보 노출",
             "Data exposure through a wrong session", ("CWE-488",)),
            ("SC-44", "제거되지 않고 남은 디버그 코드", "Leftover debug code",
             ("CWE-489", "CWE-749")),
            ("SC-45", "Public 메소드로부터 반환된 Private 배열",
             "Private array returned from a public method", ("CWE-495",)),
            ("SC-46", "Private 배열에 Public 데이터 할당",
             "Public data assigned to a private array", ("CWE-496",)),
        ]),
        ("API 오용", "API abuse", [
            ("SC-47", "DNS lookup에 의존한 보안결정", "Security decision based on a DNS lookup",
             ("CWE-247", "CWE-292", "CWE-350")),
            ("SC-48", "취약한 API 사용", "Use of an inherently dangerous API",
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
                     "행정안전부 「소프트웨어 개발보안 가이드」 점검항목", _mois()),
    "owasp": Standard("owasp", "OWASP Top 10 (2021)", "OWASP Top 10 (2021)",
                      "OWASP Top 10:2021", _owasp()),
    "cwe": Standard("cwe", "CWE", "CWE", "MITRE Common Weakness Enumeration", _cwe_items()),
}

DEFAULT = "mois"


def get(std_id: str | None) -> Standard | None:
    """기준 id -> Standard. 없거나 모르는 값이면 None(= 기준 미적용)."""
    return STANDARDS.get((std_id or "").strip().lower()) or None


def coverage(std: Standard, cwe_counts: dict[str, int]) -> list[dict]:
    """점검항목별 결과. 산출물의 '점검항목 표'가 이 모양 그대로 들어간다.

    cwe_counts: CWE -> 탐지 건수. 항목에 걸리는 CWE 가 하나도 없으면 '양호'.
    """
    out = []
    for it in std.items:
        n = sum(cwe_counts.get(c, 0) for c in it.cwes)
        out.append({"code": it.code, "name": it.name, "name_en": it.name_en,
                    "group": it.group, "group_en": it.group_en, "n": n,
                    "cwes": list(it.cwes)})
    return out


def unmapped(std: Standard, cwe_counts: dict[str, int]) -> dict[str, int]:
    """이 기준의 어느 항목에도 걸리지 않은 탐지. 숨기지 않고 따로 보고한다."""
    known = std.cwes
    return {c: n for c, n in cwe_counts.items() if c and c not in known}
