"""SCA — 잠금파일 파싱과 OSV 응답 변환. 네트워크는 타지 않는다."""
import json
import textwrap
from pathlib import Path

import pytest

from cpguard import sca


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return p


def test_requirements_only_pinned(tmp_path):
    _write(tmp_path, "requirements.txt", """
        # 주석
        django==4.2.1
        requests[security] == 2.25.0
        flask>=2.0            # 범위 지정은 버전이 확정 안 돼 조회 불가
        -r other.txt
    """)
    got = {(c.name, c.version) for c in sca.collect(tmp_path)}
    assert got == {("django", "4.2.1"), ("requests", "2.25.0")}


def test_package_lock_v3_with_license(tmp_path):
    _write(tmp_path, "package-lock.json", json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "app", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.15", "license": "MIT"},
        },
    }))
    comps = {c.name: c for c in sca.collect(tmp_path)}
    assert comps["lodash"].version == "4.17.15"
    assert comps["lodash"].ecosystem == "npm"
    assert sca.license_rows(list(comps.values()))
    assert comps["lodash"].license == "MIT"


def test_pom_skips_property_versions(tmp_path):
    _write(tmp_path, "pom.xml", """
        <project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies>
          <dependency><groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId><version>2.5.10</version></dependency>
          <dependency><groupId>x</groupId><artifactId>y</artifactId>
            <version>${rev}</version></dependency>
        </dependencies></project>
    """)
    got = {(c.name, c.version) for c in sca.collect(tmp_path)}
    assert got == {("org.apache.struts:struts2-core", "2.5.10")}


def test_xml_entity_bomb_is_not_parsed(tmp_path):
    """진단 대상은 남이 준 압축파일이다. DTD 가 있는 XML 은 읽지 않는다."""
    _write(tmp_path, "pom.xml", """
        <?xml version="1.0"?>
        <!DOCTYPE p [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>
        <project><dependencies><dependency><groupId>&b;</groupId>
          <artifactId>x</artifactId><version>1.0</version></dependency></dependencies></project>
    """)
    assert sca.collect(tmp_path) == []


def test_go_mod_and_gemfile_and_composer(tmp_path):
    _write(tmp_path, "go.mod", """
        module example.com/app
        go 1.21
        require (
            github.com/gin-gonic/gin v1.7.0
            golang.org/x/crypto v0.1.0 // indirect
        )
    """)
    _write(tmp_path, "Gemfile.lock", """
        GEM
          remote: https://rubygems.org/
          specs:
            rack (2.2.3)
            nokogiri (1.13.0)
    """)
    _write(tmp_path, "composer.lock", json.dumps({
        "packages": [{"name": "monolog/monolog", "version": "v1.25.0", "license": ["MIT"]}]}))
    got = {(c.ecosystem, c.name, c.version) for c in sca.collect(tmp_path)}
    assert ("Go", "github.com/gin-gonic/gin", "1.7.0") in got
    assert ("Go", "golang.org/x/crypto", "0.1.0") in got
    assert ("RubyGems", "rack", "2.2.3") in got
    assert ("Packagist", "monolog/monolog", "1.25.0") in got


def test_node_modules_is_skipped(tmp_path):
    _write(tmp_path, "node_modules/dep/package-lock.json",
           json.dumps({"packages": {"node_modules/x": {"version": "1.0.0"}}}))
    assert sca.collect(tmp_path) == []


def test_broken_lockfile_does_not_stop_the_scan(tmp_path):
    _write(tmp_path, "composer.lock", "{ not json")
    _write(tmp_path, "requirements.txt", "django==4.2.1\n")
    assert [c.name for c in sca.collect(tmp_path)] == ["django"]


@pytest.mark.parametrize("vuln,expected", [
    ({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}, "critical"),
    ({"severity": [{"type": "CVSS_V3", "score": "7.5"}]}, "high"),
    ({"severity": [{"type": "CVSS_V3", "score": "5.3"}]}, "medium"),
    ({"database_specific": {"severity": "MODERATE"}}, "medium"),
    ({}, "medium"),
])
def test_severity_mapping(vuln, expected):
    assert sca._severity(vuln) == expected


def test_to_findings_carries_cve_and_fix():
    comps = [sca.Component("npm", "lodash", "4.17.15", "app/package-lock.json", 1)]
    vulns = {0: [{
        "id": "GHSA-p6mc-m468-83gg",
        "aliases": ["CVE-2020-8203"],
        "summary": "Prototype pollution in lodash",
        "severity": [{"type": "CVSS_V3", "score": "7.4"}],
        "affected": [{"package": {"name": "lodash"},
                      "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.20"}]}]}],
    }]}
    f = sca.to_findings(comps, vulns)[0]
    assert f.rule_id == sca.RULE_ID and f.severity == "high" and f.cwe == sca.CWE
    assert "CVE-2020-8203" in f.message and "4.17.20" in f.message
    assert f.category == "dependency" and f.sink.loc.file.endswith("package-lock.json")


def test_same_cve_from_two_advisories_is_one_finding():
    """OSV 는 같은 CVE 를 GHSA 여러 건으로 준다. 산출물에 두 번 실리면 안 된다."""
    comps = [sca.Component("npm", "lodash", "4.17.15", "package-lock.json", 1)]
    def adv(gid, score, fixed):
        return {"id": gid, "aliases": ["CVE-2021-23337"], "summary": "Command injection",
                "severity": [{"type": "CVSS_V3", "score": score}],
                "affected": [{"package": {"name": "lodash"},
                              "ranges": [{"events": [{"fixed": fixed}]}]}]}
    out = sca.to_findings(comps, {0: [adv("GHSA-a", "5.3", "4.17.21"),
                                      adv("GHSA-b", "7.2", "4.18.0")]})
    assert len(out) == 1
    f = out[0]
    assert f.severity == "high", "등급은 가장 높은 것을 쓴다"
    assert "4.17.21" in f.message and "4.18.0" in f.message, "수정 버전은 합집합"


def test_scan_without_lockfiles_says_so(tmp_path):
    findings, note = sca.scan(tmp_path)
    assert findings == [] and "수행하지 않았다" in note


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
