"""CPGuard 명령행 인터페이스.

    cpguard scan <path> [--sarif out.json] [--quiet]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .report import console, sarif
from .scanner import scan_path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cpguard", description="CPG 기반 taint 분석 정적 보안 스캐너")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="디렉터리/파일 스캔")
    sc.add_argument("path", help="스캔할 프로젝트 경로")
    sc.add_argument("--sarif", metavar="FILE", help="SARIF 2.1.0 결과 저장 경로")
    sc.add_argument("--quiet", action="store_true", help="콘솔 상세 출력 생략")

    args = ap.parse_args(argv)

    root = Path(args.path)
    if not root.exists():
        print(f"경로 없음: {root}", file=sys.stderr)
        return 2

    findings, scanned = scan_path(root)

    if not args.quiet:
        print(console.render(findings, base=root))
    print(f"\n스캔 파일 {scanned}개 · 탐지 {len(findings)}건")

    if args.sarif:
        sarif.dump(findings, args.sarif, base=root)
        print(f"SARIF 저장: {args.sarif}")

    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
