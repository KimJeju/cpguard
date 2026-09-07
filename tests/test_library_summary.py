"""분석 대상 밖 함수(표준 라이브러리)의 동작 선언.

엔진은 소스가 없는 함수를 만나면 "인자 오염이 리턴으로 흐른다"고 과대근사하고 그 흐름을
'불확실'로 표시한다. 안전한 기본값이지만 두 가지 대가가 있다: 값을 옮기지도 않는 호출이
오탐이 되고, 동작이 뻔한 표준 라이브러리까지 진단원에게 '불확실'로 넘어간다.
"""
import textwrap

import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules
from cpguard.taint.summary import BLOCK, PROPAGATE, load_library_model

RULES = load_rules(user_dir=False)


def _scan(tmp_path, name: str, code: str):
    p = tmp_path / name
    p.write_text(textwrap.dedent(code).lstrip(), encoding="utf-8")
    return scan_file(p, RULES)


# ── 모델 자체 ────────────────────────────────────────────────────────────────

def test_shipped_model_loads():
    m = load_library_model(user_dir=False)
    assert m.by_method and m.by_path


@pytest.mark.parametrize("call,expected", [
    ("s.length", BLOCK),
    ("name.equals", BLOCK),
    ("Objects.hash", BLOCK),
    ("x.substring", PROPAGATE),
    ("String.format", PROPAGATE),
    ("sb.append", PROPAGATE),
    ("acme.doSomethingWeird", None),        # 모르는 함수는 엔진의 과대근사로 남긴다
])
def test_verdicts(call, expected):
    assert load_library_model(user_dir=False).verdict(call, ["java"]) == expected


def test_full_path_beats_method_name():
    """정적 호출은 경로 전체로 본다 — 메서드 이름만 보면 다른 것과 섞인다."""
    m = load_library_model(user_dir=False)
    assert m.verdict("Objects.equals", ["java"]) == BLOCK
    assert m.verdict("Arrays.toString", ["java"]) == PROPAGATE   # toString 은 propagate 이기도 하다


def test_language_scoping(tmp_path):
    (tmp_path / "only_go.yml").write_text(
        "id: t.go\nlanguages: [go]\nblock:\n  method: [onlyForGo]\n", encoding="utf-8")
    m = load_library_model(tmp_path, user_dir=False)
    assert m.verdict("x.onlyForGo", ["go"]) == BLOCK
    assert m.verdict("x.onlyForGo", ["java"]) is None


def test_user_overlay_overrides_shipped(tmp_path):
    """사내 유틸이 표준 이름과 겹칠 때 사용자가 바로잡을 수 있어야 한다."""
    (tmp_path / "site.yml").write_text(
        "id: site\npropagate:\n  method: [equals]\n", encoding="utf-8")
    assert load_library_model(user_dir=tmp_path).verdict("x.equals", ["java"]) == PROPAGATE


def test_broken_user_file_does_not_break_loading(tmp_path):
    (tmp_path / "bad.yml").write_text("id: [unclosed\n", encoding="utf-8")
    assert load_library_model(user_dir=tmp_path).by_method


# ── 엔진에 실제로 반영되는가 ────────────────────────────────────────────────

def test_scalar_return_does_not_reach_the_sink(tmp_path):
    """`equals` 의 리턴은 불리언이라 payload 를 SQL 로 옮길 수 없다 — 오탐이었다."""
    found = _scan(tmp_path, "Cmp.java", """
        public class Cmp {
          void run(javax.servlet.http.HttpServletRequest request, java.sql.Statement stmt)
              throws Exception {
            String id = request.getParameter("id");
            String q = "SELECT 1 WHERE ok=" + id.equals("admin") + " AND n=" + "x".equals(id);
            stmt.execute(q);
          }
        }
    """)
    assert [f.rule_id for f in found if f.rule_id == "java.sqli"] == []


def test_taint_through_declared_propagator_is_still_found(tmp_path):
    """오염을 끊어서는 안 된다 — substring 은 내용을 그대로 옮긴다."""
    found = _scan(tmp_path, "Sub.java", """
        public class Sub {
          void run(javax.servlet.http.HttpServletRequest request, java.sql.Statement stmt)
              throws Exception {
            String id = request.getParameter("id").substring(1);
            stmt.execute("SELECT * FROM t WHERE id=" + id);
          }
        }
    """)
    sqli = [f for f in found if f.rule_id == "java.sqli"]
    assert len(sqli) == 1


def test_declared_propagator_is_not_marked_uncertain(tmp_path):
    """동작이 선언된 함수만 거친 흐름은 확정이다 — 진단원이 확인할 것이 없다."""
    found = _scan(tmp_path, "Known.java", """
        public class Known {
          void run(javax.servlet.http.HttpServletRequest request, java.sql.Statement stmt)
              throws Exception {
            String id = request.getParameter("id").trim().toLowerCase();
            stmt.execute("SELECT * FROM t WHERE id=" + id);
          }
        }
    """)
    sqli = [f for f in found if f.rule_id == "java.sqli"]
    assert len(sqli) == 1 and sqli[0].uncertain is False


def test_unknown_function_is_still_uncertain(tmp_path):
    """모르는 함수는 과대근사 그대로 — 놓치는 쪽보다 낫다는 기존 판단을 유지한다."""
    found = _scan(tmp_path, "Unknown.java", """
        public class Unknown {
          void run(javax.servlet.http.HttpServletRequest request, java.sql.Statement stmt)
              throws Exception {
            String id = com.acme.Legacy.massage(request.getParameter("id"));
            stmt.execute("SELECT * FROM t WHERE id=" + id);
          }
        }
    """)
    sqli = [f for f in found if f.rule_id == "java.sqli"]
    assert len(sqli) == 1 and sqli[0].uncertain is True


def test_uncertain_does_not_leak_between_flows(tmp_path):
    """불확실 표시는 그 흐름의 성질이다 — 다른 함수의 eval() 이 옮겨붙으면 안 된다.

    Ctx 에 플래그를 두고 finding 을 낼 때만 되돌리던 탓에, 라이브러리 호출을 한 번도
    거치지 않은 SQL 주입이 같은 파일 위쪽 함수의 eval() 때문에 불확실로 찍히고 있었다.
    """
    found = _scan(tmp_path, "Leak.js", """
        function runCalc(req, res) {
          const result = eval(req.body.expr);      // 여기서 불확실이 켜진다
          res.send(String(result));
        }
        function findUser(req, res) {
          const uid = req.params.id;               // 라이브러리 호출이 없는 흐름
          db.query("SELECT * FROM users WHERE id = " + uid);
        }
    """)
    sqli = [f for f in found if f.rule_id == "js.sqli"]
    assert len(sqli) == 1 and sqli[0].uncertain is False
