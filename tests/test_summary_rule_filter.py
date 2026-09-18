"""프로젝트 스캔의 규칙별 요약 계산은 존재하는 언어의 규칙에만 한정돼야 한다.

scanner 의 `active` 필터가 싱크 리터럴의 텍스트 존재만 보고 언어를 안 봐서, Java 전용
프로젝트에서도 `exec`·`query`·`write` 같은 흔한 이름 때문에 cpp·php·js·… 규칙 49개의
요약을 함수 전부에 대해 계산하고 있었다. 그 요약은 파일별 `applicable`(언어 필터)에서
한 번도 쓰이지 않는다 — 데이터 흐름 단계 시간의 86% 가 낭비였다(java200: 83s → 17s).
"""
from cpguard import scanner
from cpguard.taint import engine

_JAVA = """
import java.io.*;
import javax.servlet.http.*;
public class Svc extends HttpServlet {
    // exec query write system eval open include popen fopen render send
    public void doPost(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        String p = req.getParameter("cmd");
        Runtime.getRuntime().exec(p);
    }
}
"""


def test_summaries_only_for_present_languages(tmp_path, monkeypatch):
    (tmp_path / "Svc.java").write_text(_JAVA, encoding="utf-8")
    seen: list[str] = []
    real = engine.compute_summaries

    def spy(registry, rule):
        seen.append(rule.id)
        return real(registry, rule)

    monkeypatch.setattr(scanner.engine, "compute_summaries", spy)
    findings, _ = scanner.scan_path(tmp_path, jobs=1)

    assert any(f.rule_id == "java.command-injection" for f in findings), "회귀: 탐지 자체가 사라짐"
    assert seen, "요약 계산이 한 번도 안 돌았다"
    wrong = [r for r in seen if not r.startswith("java.")]
    assert not wrong, f"존재하지 않는 언어의 규칙까지 요약 계산: {wrong[:8]} (총 {len(wrong)})"
