"""파생값 가드 — 검증한 것이 원본이 아니라 원본의 **투영**일 때.

실제 코드에서 SSRF 를 막는 방법은 URL 문자열 자체를 검사하는 게 아니다. 파싱해서
호스트를 꺼내고, 그 호스트를 검사하고, 통과하면 **원래 문자열**로 요청한다.

    parsedURL, _ := url.Parse(data)         // data 가 오염
    if !allowed[parsedURL.Hostname()] { 거부; return }
    http.Get(data)                          // 검증됐지만 우리 env 에는 data 가 그대로 오염

지금 엔진은 조건이 검사한 경로(`parsedURL.Hostname`)만 씻는다. 정작 싱크에 닿는
`data` 는 그대로 남아 오탐이 된다. go/gin 오탐 148건 중 87건(59%)이 이 형태다.

건전성은 일반적으로 보장되지 않는다 — 투영을 검사했다고 원본이 안전한 것은 아니다
(호스트를 검사해도 경로·질의는 그대로다). 그래서 판단을 코드에 미리 박지 않고 8개
코퍼스 15개 스위트를 전부 재 본 뒤 켰다. Go +0.15, Ruby +0.04, 7개 스위트 변화 없음,
JS·TS 는 스위트당 2건씩 재현율을 잃는다(허용 목록이 내부 도메인을 허용하는 형태라
흐름 분석으로는 구분할 수 없다). 전후 표는 bench/README.md 에 있다.

아래 '취약' 항목들이 그 대가의 상한선이다. 여기가 깨지면 재현율을 팔아 정밀도를 산 것이다.

여기 등장하는 http.Get·exec 은 탐지 대상 문자열이다. 임시 파일에 텍스트로 쓴 뒤
스캐너에 넣어 "이 흐름을 잡는가"를 묻는 용도이며, 실행하지 않는다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules(user_dir=False)

TPL = """package testcode

import (
	"net"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"
)

func Handle(c *gin.Context) {
	data := c.Query("id")
%s
}
"""

#: (이름, 기대, 본문). 본문은 data 가 오염된 상태에서 시작한다.
CASES = [
    # --- 씻겨야 하는 것: 거부 분기가 파생값을 검사하고 돌아간다 ---
    ("동등비교 거부", "안전", '''	parsedURL, err := url.Parse(data)
	if err != nil {
		return
	}
	host := parsedURL.Hostname()
	if host == "metadata.google.internal" || host == "metadata" {
		return
	}
	http.Get(data)'''),

    ("조회표 거부", "안전", '''	parsedURL, err := url.Parse(data)
	if err != nil {
		return
	}
	allowed := map[string]bool{"api.svc.cluster": true}
	if !allowed[parsedURL.Hostname()] {
		return
	}
	http.Get(data)'''),

    ("IP 분류 거부", "안전", '''	parsedURL, err := url.Parse(data)
	if err != nil {
		return
	}
	ip := net.ParseIP(parsedURL.Hostname())
	if ip != nil && (ip.IsPrivate() || ip.IsLoopback()) {
		return
	}
	http.Get(data)'''),

    # --- 씻기면 안 되는 것: 여기가 무너지면 재현율을 팔아 정밀도를 산 것이다 ---
    ("가드 없음", "취약", '	http.Get(data)'),

    ("길이 검사는 검증이 아니다", "취약", '''	if len(data) > 100 {
		return
	}
	http.Get(data)'''),

    ("무관한 값 검사", "취약", '''	mode := "fixed"
	if mode != "fixed" {
		return
	}
	http.Get(data)'''),

    ("거부하지 않는 분기", "취약", '''	parsedURL, err := url.Parse(data)
	if err != nil {
		return
	}
	host := parsedURL.Hostname()
	if host == "evil.example" {
		data = data + "?blocked=1"
	}
	http.Get(data)'''),

    ("검사 뒤 다시 오염", "취약", '''	parsedURL, err := url.Parse(data)
	if err != nil {
		return
	}
	if parsedURL.Hostname() == "metadata" {
		return
	}
	data = c.Query("other")
	http.Get(data)'''),
]


@pytest.mark.parametrize("name,want,body", CASES, ids=[c[0] for c in CASES])
def test_derived_guard(tmp_path, name, want, body):
    f = tmp_path / "probe.go"
    f.write_text(TPL % body, encoding="utf-8")
    hit = any(x.rule_id.startswith("go.") for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"


CPP_TPL = """#include <string>
#include <regex>
#include <httplib.h>

void handle(const httplib::Request &req, httplib::Response &res) {
    std::string user_input = req.get_param_value("input");
%s
}
"""

#: 삼항 허용 목록 — `검사(x) ? x : 기본값`. C++ 코퍼스 오탐 130건 중 117건이 이 형태였다.
#: 참 분기를 타면 x 는 비교한 상수 중 하나이고 거짓 분기는 기본값이다. 어느 쪽이든
#: 미리 정해진 값이라 과대근사가 아니라 확정이다.
TERNARY = [
    ("동등비교 허용목록", "안전",
     '    std::string safe = (user_input == "asc" || user_input == "desc")\n'
     '        ? user_input : std::string("asc");\n    std::system(safe.c_str());'),

    ("부등비교 뒤집기", "안전",
     '    std::string safe = (user_input != "asc")\n'
     '        ? std::string("asc") : user_input;\n    std::system(safe.c_str());'),

    ("정규식 검사", "안전",
     '    static const std::regex re("^[a-z]+$");\n'
     '    std::string safe = std::regex_match(user_input, re)\n'
     '        ? user_input : std::string("default");\n    std::system(safe.c_str());'),

    # --- 아래가 경계선이다 ---
    ("다른 변수를 검사", "취약",
     '    std::string other = "fixed";\n'
     '    std::string safe = (other == "fixed") ? user_input : std::string("asc");\n'
     '    std::system(safe.c_str());'),

    ("섞인 OR 은 증명이 안 된다", "취약",
     '    std::string other = "fixed";\n'
     '    std::string safe = (user_input == "asc" || other == "x")\n'
     '        ? user_input : std::string("asc");\n    std::system(safe.c_str());'),

    ("기본값이 오염", "취약",
     '    std::string safe = (user_input == "asc")\n'
     '        ? std::string("asc") : user_input;\n    std::system(safe.c_str());'),

    ("검사 없는 삼항", "취약",
     '    std::string safe = user_input.empty() ? std::string("asc") : user_input;\n'
     '    std::system(safe.c_str());'),
]


@pytest.mark.parametrize("name,want,body", TERNARY, ids=[c[0] for c in TERNARY])
def test_ternary_constant_set(tmp_path, name, want, body):
    f = tmp_path / "probe.cpp"
    f.write_text(CPP_TPL % body, encoding="utf-8")
    hit = any(x.rule_id == "cpp.command-injection" for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"
