"""CPGuard 명령행 인터페이스.

    cpguard scan <path> [--sarif out.json] [--quiet]
"""
from __future__ import annotations

import argparse
from collections import Counter
import multiprocessing
import sys
from pathlib import Path

from .report import console, sarif
from .scanner import scan_path


def _force_utf8_output() -> None:
    """한글 Windows 콘솔(cp949)은 em-dash·화살표 같은 문자를 인코딩하지 못해
    print 에서 UnicodeEncodeError 로 죽는다. 한국어 우선 도구이므로 출력 스트림을
    utf-8 로 맞춰 크래시를 없앤다. 리다이렉트·캡처된 스트림이면 조용히 넘어간다."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass


def main(argv: list[str] | None = None) -> int:
    multiprocessing.freeze_support()  # frozen 앱에서 워커가 앱을 재실행하지 않도록
    _force_utf8_output()
    ap = argparse.ArgumentParser(prog="cpguard", description="CPG 기반 taint 분석 정적 보안 스캐너")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="디렉터리/파일 스캔")
    sc.add_argument("path", help="스캔할 프로젝트 경로")
    sc.add_argument("--sarif", metavar="FILE", help="SARIF 2.1.0 결과 저장 경로")
    sc.add_argument("--xlsx", metavar="FILE", help="고객 제출용 분석목록표(xlsx) 저장 경로")
    sc.add_argument("--standard", action="append", metavar="ID",
                    choices=["mois", "efs", "owasp", "cwe"],
                    help="점검 기준(여러 번 지정 가능) — mois(행정안전부 보안약점) · "
                         "efs(전자금융감독규정 웹 취약점) · owasp(Top 10) · cwe. "
                         "지정하면 점검항목별 판정을 출력하고 xlsx 에 점검항목 시트를 넣는다")
    sc.add_argument("--quiet", action="store_true", help="콘솔 상세 출력 생략")
    sc.add_argument("--triage", action="store_true",
                    help="LLM 트리아지로 오탐 재검증")
    sc.add_argument("--sca", action="store_true",
                    help="오픈소스 컴포넌트의 알려진 취약점 점검(잠금파일 → OSV.dev). "
                         "패키지 이름·버전이 외부로 나가므로 기본은 꺼져 있다")
    sc.add_argument("--provider", choices=["claude", "openai", "gemini"],
                    help="트리아지에 쓸 LLM (생략 시 키가 있는 것을 자동 선택)")
    sc.add_argument("--model", help="프로바이더의 모델명 재정의")
    sc.add_argument("-j", "--jobs", type=int, default=1,
                    help="파싱 병렬 워커 수 (기본 1; 대형 프로젝트에서만 이득)")
    sc.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info", "none"],
                    default=None,
                    help="CI 게이트: 이 등급 이상 탐지 시 종료코드 1. 'none'=항상 0. 미지정=탐지 있으면 1.")

    sv = sub.add_parser("serve", help="웹 대시보드 실행 (zip 업로드 진단)")
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--no-browser", action="store_true", help="브라우저 자동 실행 안 함")

    ap_app = sub.add_parser("app", help="독립 데스크톱 창으로 실행 (브라우저 아님)")
    ap_app.add_argument("--port", type=int, help="사용할 포트 (생략 시 자동 선택)")
    ap_app.add_argument("--debug", action="store_true", help="웹뷰 디버그 도구 활성화")

    args = ap.parse_args(argv)

    if args.cmd == "serve":
        from .web.run import serve
        serve(host=args.host, port=args.port, open_browser=not args.no_browser)
        return 0

    if args.cmd == "app":
        from .desktop import DesktopUnavailable, launch
        try:
            launch(port=args.port, debug=args.debug)
        except DesktopUnavailable as e:
            print(f"[데스크톱 창 실패] {e}", file=sys.stderr)
            return 1
        return 0

    root = Path(args.path)
    if not root.exists():
        print(f"경로 없음: {root}", file=sys.stderr)
        return 2

    findings, report = scan_path(root, jobs=args.jobs)

    if args.sca:
        from . import sca
        dep_findings, sca_note = sca.scan(root)
        findings += dep_findings
        print(sca_note)

    if args.triage and findings:
        from .triage import TriageUnavailable, triage_findings
        try:
            triage_findings(findings, provider=args.provider, model=args.model)
        except TriageUnavailable as e:
            print(f"[트리아지 건너뜀] {e}", file=sys.stderr)

    if not args.quiet:
        print(console.render(findings, base=root))
    print(f"\n{report.summary()} · 탐지 {len(findings)}건")
    if report.failed:
        print("분석하지 못한 파일:", file=sys.stderr)
        for path, why in report.failed[:10]:
            print(f"  - {path}: {why}", file=sys.stderr)
        if len(report.failed) > 10:
            print(f"  ... 외 {len(report.failed) - 10}개", file=sys.stderr)

    if args.sarif:
        sarif.dump(findings, args.sarif, base=root)
        print(f"SARIF 저장: {args.sarif}")

    if args.xlsx:
        from .report import excel
        excel.write_workbook(findings, args.xlsx, project=root.name, base=root,
                             standards=args.standard or [])
        print(f"분석목록표 저장: {args.xlsx}")

    if args.standard:
        from . import standards
        counts = Counter(c for f in findings
                         if (c := (f.cwe or "").strip().upper()))
        avail = standards.rule_cwes()
        for sid in args.standard:
            std = standards.get(sid)
            rows = standards.coverage(std, counts, avail)
            violated = [r for r in rows if r["verdict"] == standards.VIOLATED]
            skipped = [r for r in rows if r["verdict"] == standards.NOT_COVERED]
            print()
            print(f"[점검 기준] {std.name} — {len(rows)}개 항목 중 "
                  f"위반 {len(violated)} · 양호 {len(rows) - len(violated) - len(skipped)} · "
                  f"진단 대상 아님 {len(skipped)}")
            for r in violated:
                print(f"  취약  {r['name']}  ({r['n']}건)")
            if skipped:
                # 규칙이 없어 못 본 항목을 양호로 세면 안 한 점검을 했다고 쓰는 셈이다.
                print("  진단 대상 아님(해당 규칙 없음): "
                      + ", ".join(r["name"] for r in skipped[:8])
                      + (f" 외 {len(skipped) - 8}개" if len(skipped) > 8 else ""))
            if um := standards.unmapped(std, counts):
                print("  기준 미매핑: "
                      + ", ".join(f"{c}({n})" for c, n in sorted(um.items(), key=lambda kv: -kv[1])))

    # CI 게이트: --fail-on 지정 시 그 등급 이상 탐지일 때만 실패 코드. 미지정 시 레거시(탐지 있으면 1).
    if args.fail_on is not None:
        if args.fail_on == "none":
            return 0
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        thr = order[args.fail_on]
        return 1 if any(order.get(f.severity, 9) <= thr for f in findings) else 0
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
