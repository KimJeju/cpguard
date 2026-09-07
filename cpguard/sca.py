"""SCA — 오픈소스 컴포넌트의 알려진 취약점(CVE) 점검.

정적 분석은 우리가 쓴 코드만 본다. 국내 진단 사업에서 실제로 요구되는 항목 하나는
"쓰고 있는 오픈소스에 알려진 취약점이 있는가" 인데, 그건 소스가 아니라 의존성 목록에
있다. 여기서는 잠금파일(lockfile)을 읽어 컴포넌트 목록을 만들고 OSV.dev 에 조회한다.

설계 상의 선택 두 가지:

* **취약점 DB 를 들고 있지 않는다.** OSV.dev 가 npm·PyPI·Maven·Go·RubyGems·Packagist·
  NuGet 를 한 스키마로 제공하고 무료다. 오프라인 진단이 요구되면 그때 스냅샷을 미러한다.
* **기본 꺼짐.** 조회는 패키지 이름·버전을 외부(api.osv.dev)로 보낸다. 진단 대상의
  의존성 목록은 그 자체로 정보이므로, 사용자가 ``--sca`` 로 명시할 때만 나간다.

라이선스는 잠금파일이 이미 들고 있는 것만 읽는다(npm·composer). 나머지 생태계까지
보려면 레지스트리 메타데이터 조회가 따로 필요한데, 그건 여기 범위가 아니다.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path

from .ir import Loc
from .report.finding import Finding, Step

OSV_API = "https://api.osv.dev"
RULE_ID = "sca.vulnerable-dependency"
CWE = "CWE-1395"
OWASP = "A06:2021-Vulnerable and Outdated Components"

#: 잠금파일 하나에서 뽑을 컴포넌트 상한. 모노레포의 package-lock 은 수만 줄이 나온다.
MAX_COMPONENTS = 5000
#: OSV querybatch 한 번에 보낼 개수(API 상한 1000).
BATCH = 500


@dataclass
class Component:
    ecosystem: str          # OSV ecosystem 이름 (npm / PyPI / Maven / Go / ...)
    name: str
    version: str
    file: str               # 컴포넌트를 발견한 잠금파일 (상대경로 아님, 호출측이 정리)
    line: int = 1
    license: str = ""       # 잠금파일이 들고 있을 때만


def _line_of(lines: list[str], *needles: str) -> int:
    """잠금파일에서 그 컴포넌트가 적힌 줄. 못 찾으면 1.

    구조화 파서(json/xml)는 줄 번호를 주지 않는데, 검토 화면의 코드 뷰어는 줄로 이동한다.
    파일 첫 줄로 보내면 진단원이 직접 찾아야 하므로 원문에서 한 번 훑는다.
    """
    for i, raw in enumerate(lines, 1):
        if all(n in raw for n in needles):
            return i
    return 1


# ── 잠금파일 파서 ────────────────────────────────────────────────────────────
# 각 파서는 실패해도 빈 목록을 돌려준다. 의존성 하나 못 읽었다고 진단이 멈추면 안 된다.

def _requirements(path: Path) -> list[Component]:
    """requirements.txt — ``==`` 로 고정된 것만. 범위 지정은 버전이 확정 안 돼 조회 불가."""
    out = []
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        m = re.match(r"^([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9._!+-]+)", line)
        if m:
            out.append(Component("PyPI", m.group(1), m.group(2), str(path), i))
    return out


def _package_lock(path: Path) -> list[Component]:
    """package-lock.json v2/v3 의 ``packages`` 맵. v1 의 ``dependencies`` 도 훑는다."""
    text = path.read_text(encoding="utf-8", errors="replace")
    d = json.loads(text)
    lines = text.splitlines()
    out = []
    for key, meta in (d.get("packages") or {}).items():
        if not key or not isinstance(meta, dict) or not meta.get("version"):
            continue
        name = meta.get("name") or key.split("node_modules/")[-1]
        if not name:
            continue
        lic = meta.get("license")
        out.append(Component("npm", name, meta["version"], str(path),
                             line=_line_of(lines, f'"{key}"'),
                             license=lic if isinstance(lic, str) else ""))

    def walk(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                out.append(Component("npm", name, meta["version"], str(path),
                                     line=_line_of(lines, f'"{name}"')))
                walk(meta.get("dependencies") or {})

    if not out:
        walk(d.get("dependencies") or {})
    return out


#: XML 잠금파일 상한. 진단 대상은 남이 준 압축파일이고, ElementTree 는 내부 엔티티를
#: 실제로 전개한다(billion laughs). 정상 pom.xml 은 이 크기를 넘지 않는다.
MAX_XML_BYTES = 5 * 1024 * 1024


def _parse_xml(path: Path):
    """신뢰할 수 없는 XML 을 읽는다. 크기 초과·DTD 선언이 있으면 읽지 않는다.

    pom.xml / packages.config 에 DOCTYPE 이 필요한 경우는 없다. 엔티티 폭탄과 DTD 를
    통째로 막는 쪽이, 파서를 바꾸거나 의존성을 늘리는 것보다 싸고 확실하다.
    """
    import xml.etree.ElementTree as ET
    try:
        if path.stat().st_size > MAX_XML_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            return None
        return ET.fromstring(text)
    except (OSError, ET.ParseError):
        return None


def _pom(path: Path) -> list[Component]:
    """pom.xml — 리터럴 버전만. ``${revision}`` 같은 프로퍼티는 해석하지 않는다."""
    root = _parse_xml(path)
    if root is None:
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}
    def find(el, tag):
        r = el.find(f"m:{tag}", ns) if ns else el.find(tag)
        return (r.text or "").strip() if r is not None and r.text else ""
    out = []
    for dep in (root.iter("{%s}dependency" % ns["m"]) if ns else root.iter("dependency")):
        g, a, v = find(dep, "groupId"), find(dep, "artifactId"), find(dep, "version")
        if g and a and v and "${" not in v:
            out.append(Component("Maven", f"{g}:{a}", v, str(path),
                                 line=_line_of(lines, f"<artifactId>{a}<")))
    return out


def _go_mod(path: Path) -> list[Component]:
    """go.mod 의 require 블록. ``// indirect`` 도 포함한다 — 실제로 링크되기 때문."""
    out = []
    text = path.read_text(encoding="utf-8", errors="replace")
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.split("//", 1)[0].strip()
        if line.startswith("require "):
            line = line[len("require "):].strip()
        if line in ("require (", ")", ""):
            continue
        m = re.match(r"^([\w.\-/~]+\.[\w.\-/~]+)\s+v([0-9][\w.\-+]*)$", line)
        if m:
            out.append(Component("Go", m.group(1), m.group(2), str(path), i))
    return out


def _gemfile_lock(path: Path) -> list[Component]:
    out, in_specs = [], False
    for i, raw in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if raw.strip() in ("GEM", "GIT", "PATH"):
            in_specs = False
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            m = re.match(r"^ {4}([A-Za-z0-9._-]+) \(([0-9][^)]*)\)$", raw)
            if m:
                out.append(Component("RubyGems", m.group(1), m.group(2), str(path), i))
    return out


def _composer_lock(path: Path) -> list[Component]:
    text = path.read_text(encoding="utf-8", errors="replace")
    d = json.loads(text)
    lines = text.splitlines()
    out = []
    for section in ("packages", "packages-dev"):
        for p in d.get(section) or []:
            if p.get("name") and p.get("version"):
                lic = p.get("license") or []
                out.append(Component("Packagist", p["name"], p["version"].lstrip("v"), str(path),
                                     line=_line_of(lines, f'"{p["name"]}"'),
                                     license=", ".join(lic) if isinstance(lic, list) else str(lic)))
    return out


def _packages_config(path: Path) -> list[Component]:
    root = _parse_xml(path)
    if root is None:
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [Component("NuGet", e.get("id", ""), e.get("version", ""), str(path),
                      line=_line_of(lines, f'id="{e.get("id")}"'))
            for e in root.iter("package") if e.get("id") and e.get("version")]


PARSERS = {
    "requirements.txt": _requirements,
    "package-lock.json": _package_lock,
    "pom.xml": _pom,
    "go.mod": _go_mod,
    "Gemfile.lock": _gemfile_lock,
    "composer.lock": _composer_lock,
    "packages.config": _packages_config,
}
#: 잠금파일 자체가 들어 있을 리 없는 디렉터리 — 스캔 대상이 아니다.
_SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", "target", ".venv", "venv"}


def collect(root: str | Path) -> list[Component]:
    """대상 트리에서 잠금파일을 찾아 컴포넌트 목록을 만든다. 이름+버전으로 중복 제거."""
    root = Path(root)
    found: dict[tuple[str, str, str], Component] = {}
    for p in root.rglob("*"):
        if p.name not in PARSERS or not p.is_file():
            continue
        if _SKIP_DIRS & set(p.parts):
            continue
        try:
            comps = PARSERS[p.name](p)
        except Exception:
            continue                    # 깨진 잠금파일 하나가 진단을 멈추면 안 된다
        for c in comps:
            if c.name and c.version:
                found.setdefault((c.ecosystem, c.name, c.version), c)
            if len(found) >= MAX_COMPONENTS:
                return list(found.values())
    return list(found.values())


# ── OSV 조회 ─────────────────────────────────────────────────────────────────

def _call(url: str, payload: dict | None, timeout: float) -> dict:
    """payload 가 있으면 POST, 없으면 GET. /v1/vulns/<id> 는 GET 만 받는다."""
    import urllib.request
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={"Content-Type": "application/json", "User-Agent": "CPGuard-SCA"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def query_osv(components: list[Component], timeout: float = 30.0) -> dict[int, list[dict]]:
    """컴포넌트 인덱스 -> 취약점 상세 목록. 네트워크가 막히면 빈 dict."""
    hits: dict[int, list[str]] = {}
    for start in range(0, len(components), BATCH):
        chunk = components[start:start + BATCH]
        payload = {"queries": [{"package": {"name": c.name, "ecosystem": c.ecosystem},
                                "version": c.version} for c in chunk]}
        try:
            res = _call(f"{OSV_API}/v1/querybatch", payload, timeout)
        except Exception:
            return {}                   # 오프라인·차단 환경 — 호출측이 '미수행'으로 처리
        for off, r in enumerate(res.get("results") or []):
            ids = [v["id"] for v in (r.get("vulns") or []) if v.get("id")]
            if ids:
                hits[start + off] = ids

    # 상세는 취약점 id 기준으로 한 번만 받는다 — 같은 CVE 가 여러 패키지에 걸린다
    detail: dict[str, dict] = {}
    for vid in {v for ids in hits.values() for v in ids}:
        try:
            detail[vid] = _call(f"{OSV_API}/v1/vulns/{vid}", None, timeout)
        except Exception:
            detail[vid] = {"id": vid}
    return {i: [detail.get(v, {"id": v}) for v in ids] for i, ids in hits.items()}


# ── 결과 변환 ────────────────────────────────────────────────────────────────

_SEV_BY_SCORE = ((9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"))


def _severity(vuln: dict) -> str:
    """CVSS 점수 -> 우리 등급. 점수가 없으면 OSV database_specific 라벨, 그것도 없으면 medium."""
    for s in vuln.get("severity") or []:
        score = str(s.get("score") or "")
        # CVSS 벡터만 오고 점수가 없는 항목이 흔하다 — 그건 아래 라벨로 넘긴다
        if m := re.match(r"^([0-9.]+)$", score):
            v = float(m.group(1))
            for lo, name in _SEV_BY_SCORE:
                if v >= lo:
                    return name
    label = str((vuln.get("database_specific") or {}).get("severity") or "").lower()
    return {"critical": "critical", "high": "high", "moderate": "medium",
            "medium": "medium", "low": "low"}.get(label, "medium")


def _fixed_versions(vuln: dict, name: str) -> list[str]:
    out = []
    for aff in vuln.get("affected") or []:
        if (aff.get("package") or {}).get("name") not in (name, None):
            continue
        for rng in aff.get("ranges") or []:
            out += [e["fixed"] for e in rng.get("events") or [] if e.get("fixed")]
    return sorted(set(out))


_SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def to_findings(components: list[Component], vulns: dict[int, list[dict]]) -> list[Finding]:
    """OSV 결과를 일반 탐지로 바꾼다 — 기존 보고서·SARIF·검토 화면이 그대로 처리한다.

    한 CVE 가 서로 다른 권고(GHSA 등) 여러 건으로 오는 일이 흔하다. 컴포넌트+CVE 로
    묶어 한 건으로 낸다 — 같은 취약점을 두 번 실으면 진단원이 손으로 걸러야 한다.
    등급은 가장 높은 것, 수정 버전은 합집합을 쓴다(유지보수 계열이 여럿이면 여럿 나온다).
    """
    merged: dict[tuple[int, str], dict] = {}
    for idx, vlist in sorted(vulns.items()):
        for v in vlist:
            aliases = [a for a in (v.get("aliases") or []) if a.startswith("CVE-")]
            cve = aliases[0] if aliases else v.get("id", "")
            key = (idx, cve)
            cur = merged.setdefault(key, {"sev": "info", "fixed": set(), "summary": ""})
            sev = _severity(v)
            if _SEV_ORDER.index(sev) > _SEV_ORDER.index(cur["sev"]):
                cur["sev"] = sev
            cur["fixed"].update(_fixed_versions(v, components[idx].name))
            if not cur["summary"]:
                cur["summary"] = (v.get("summary") or "").strip()

    out: list[Finding] = []
    for (idx, cve), m in merged.items():
        c = components[idx]
        fixed = sorted(m["fixed"])
        if len(fixed) > 1:
            fix = f" 조치: 사용 중인 계열에 맞춰 {', '.join(fixed)} 중 하나 이상으로 갱신."
        elif fixed:
            fix = f" 조치: {fixed[0]} 이상으로 갱신."
        else:
            fix = " 상위 버전 공지를 확인하십시오."
        msg = (f"{c.name} {c.version} 에 알려진 취약점 {cve} 이 있습니다."
               + (f" {m['summary']}" if m["summary"] else "") + fix)
        loc = Loc(c.file, c.line, 0, c.line, 0, 0, 0)
        out.append(Finding(
            rule_id=RULE_ID, message=msg, severity=m["sev"], cwe=CWE, owasp=OWASP,
            steps=[Step("sink", loc, f"{c.ecosystem}:{c.name}@{c.version}  {cve}")],
            category="dependency", precision="high",
            # 검토 화면의 라벨. 규칙 id 는 SCA 탐지 전부 같아서 목록에서 구분이 안 된다
            matched_value=f"{c.name}@{c.version} · {cve}",
        ))
    return out


def scan(root: str | Path, timeout: float = 30.0) -> tuple[list[Finding], str, list[Component]]:
    """(탐지, 요약 한 줄, 컴포넌트 목록).

    컴포넌트 목록은 취약점이 없어도 돌려준다 — 그 자체가 산출물(SBOM)이다.
    """
    comps = collect(root)
    if not comps:
        return [], "SCA: 잠금파일을 찾지 못해 오픈소스 컴포넌트 점검을 수행하지 않았다.", []
    vulns = query_osv(comps, timeout)
    if not vulns:
        # 취약점이 없어서 비었는지, 조회가 막혀서 비었는지 구분이 안 된다. 산출물에는
        # 확정할 수 있는 것만 쓴다 — 진단원이 오프라인이면 다시 돌린다.
        return [], (f"SCA: 컴포넌트 {len(comps)}건을 조회했다. 알려진 취약점 없음 "
                    f"(외부 조회가 차단된 환경이면 결과가 비어 보일 수 있다)."), comps
    findings = to_findings(comps, vulns)
    return (findings,
            f"SCA: 컴포넌트 {len(comps)}건 중 {len(findings)}건의 알려진 취약점을 확인했다.",
            comps)


def sbom_rows(components: list[Component]) -> list[list[str]]:
    """[생태계, 이름, 버전, 라이선스]. 라이선스는 잠금파일이 들고 있는 것만 값이 찬다.

    보고서에 그대로 실리는 형태(JSON 직렬화 가능)로 낸다.
    """
    return sorted([c.ecosystem, c.name, c.version, c.license or "-"] for c in components)
