"""TS 관용구 탐지 회귀 방지.

TS 는 라벨링된 정답지가 없다(OWASP Benchmark 는 자바·파이썬만 있다). 실제 TS 백엔드
코드에서 흔한 형태를 최소 재현으로 직접 물어본다. 각 항목은 '취약'(탐지되어야 함)
이거나 '안전'(탐지되면 안 됨)이다.

여기 등장하는 cp.exec 는 탐지 대상 문자열이다. 임시 파일에 텍스트로 쓴 뒤 스캐너에
넣어 "이 흐름을 잡는가"를 묻는 용도이며, 실행하지 않는다.
"""
import pytest

from cpguard.scanner import scan_file
from cpguard.taint.spec import load_rules

RULES = load_rules(user_dir=False)

# 익스프레스 핸들러 본문 자리(%s). TS 라 타입이 붙는다.
TPL = ("import * as cp from 'child_process';\n"
       "import express, { Request, Response } from 'express';\n"
       "const app = express();\n"
       "app.post('/x', async (req: Request, res: Response): Promise<void> => {\n%s\n});\n")

# 파일 전체를 직접 쓰는 항목(%s 없음)
WHOLE = "WHOLE"

CASES = [
    # ---- 타입 표기 자체가 흐름을 끊지 않는가 ----
    ("타입 표기 변수", "취약", "  const x: string = req.query.x as string;\n  cp.exec(x);"),
    ("as 캐스팅", "취약", "  const x = req.query.x as string;\n  cp.exec(x);"),
    ("as unknown as", "취약", "  const x = req.query.x as unknown as string;\n  cp.exec(x);"),
    ("꺾쇠 캐스팅", "취약", "  const x = req.body.cmd;\n  cp.exec(<string>x);"),
    ("논널 단언", "취약", "  const x = req.query.x!;\n  cp.exec(x);"),
    ("satisfies", "취약", "  const x = req.query.x satisfies unknown;\n  cp.exec(String(x));"),
    ("옵셔널 체이닝+단언", "취약", "  const x = req.query?.x!;\n  cp.exec(x as string);"),
    ("제네릭 호출", "취약",
     "  const x = JSON.parse<string>(req.body.raw);\n  cp.exec(x);"),
    ("타입 표기 구조분해", "취약",
     "  const { x }: { x: string } = req.query as any;\n  cp.exec(x);"),
    ("타입 표기 파라미터 함수", "취약",
     "  function run(v: string): void { cp.exec(v); }\n  run(req.query.x as string);"),
    ("화살표 반환타입", "취약",
     "  const run = (v: string): void => { cp.exec(v); };\n  run(req.query.x as string);"),
    ("enum 키 접근", "취약",
     "  enum K { A = 'a' }\n  const m: Record<string, string> = {};\n"
     "  m[K.A] = req.query.x as string;\n  cp.exec(m['a']);"),
    ("readonly 배열", "취약",
     "  const a: readonly string[] = [req.query.x as string];\n  cp.exec(a[0]);"),
    # ---- 클래스·데코레이터(NestJS 계열) ----
    ("클래스 필드 경유", "취약", WHOLE + """
import * as cp from 'child_process';
export class Svc {
  private cmd: string;
  constructor(input: string) { this.cmd = input; }
  run(): void { cp.exec(this.cmd); }
}
export function handler(req: any): void { new Svc(req.query.x).run(); }
"""),
    ("생성자 파라미터 프로퍼티", "취약", WHOLE + """
import * as cp from 'child_process';
export class Svc {
  constructor(private readonly cmd: string) {}
  run(): void { cp.exec(this.cmd); }
}
export function handler(req: any): void { new Svc(req.query.x).run(); }
"""),
    ("접근 제어자 메서드", "취약", WHOLE + """
import * as cp from 'child_process';
export class Svc {
  public run(v: string): void { cp.exec(v); }
}
export function handler(req: any): void { new Svc().run(req.query.x); }
"""),
    ("정적 메서드", "취약", WHOLE + """
import * as cp from 'child_process';
export class Svc {
  static run(v: string): void { cp.exec(v); }
}
export function handler(req: any): void { Svc.run(req.body.cmd); }
"""),
    ("추상 클래스 구현", "취약", WHOLE + """
import * as cp from 'child_process';
abstract class Base { abstract run(v: string): void; }
export class Svc extends Base { run(v: string): void { cp.exec(v); } }
export function handler(req: any): void { new Svc().run(req.query.x); }
"""),
    ("NestJS 데코레이터 소스", "취약", WHOLE + """
import * as cp from 'child_process';
import { Controller, Post, Body, Query } from '@nestjs/common';
@Controller('x')
export class C {
  @Post()
  run(@Query('name') name: string): void { cp.exec(name); }
}
"""),
    ("네임스페이스 안 함수", "취약", WHOLE + """
import * as cp from 'child_process';
export namespace N { export function run(v: string): void { cp.exec(v); } }
export function handler(req: any): void { N.run(req.query.x); }
"""),
    ("인터페이스 통과", "취약", WHOLE + """
import * as cp from 'child_process';
interface Opts { cmd: string; }
export function handler(req: any): void {
  const o: Opts = { cmd: req.query.x };
  cp.exec(o.cmd);
}
"""),
    ("타입 별칭 통과", "취약", WHOLE + """
import * as cp from 'child_process';
type Opts = { cmd: string };
export function handler(req: any): void {
  const o: Opts = { cmd: req.query.x };
  cp.exec(o.cmd);
}
"""),
    # ---- 정밀도 ----
    ("다른 필드 읽기", "안전", WHOLE + """
import * as cp from 'child_process';
interface Opts { cmd: string; safe: string; }
export function handler(req: any): void {
  const o: Opts = { cmd: req.query.x, safe: 'ls' };
  cp.exec(o.safe);
}
"""),
    ("숫자 타입 변환", "안전", "  const n: number = Number(req.query.x);\n  cp.exec('ls ' + n);"),
    ("길이만 사용", "안전",
     "  const x = req.query.x as string;\n  cp.exec('ls ' + x.length);"),
    ("타입 가드 후 숫자", "안전",
     "  const x = parseInt(req.query.x as string, 10);\n  cp.exec(`ls ${x}`);"),
    # ---- async / 제네릭 컨테이너 ----
    ("await 함수 경유", "취약",
     "  async function run(v: string): Promise<void> { cp.exec(v); }\n"
     "  await run(req.query.x as string);"),
    ("Map 컨테이너", "취약",
     "  const m = new Map<string, string>();\n"
     "  m.set('k', req.query.x as string);\n  cp.exec(m.get('k') as string);"),
    ("배열 제네릭 map", "취약",
     "  const a: string[] = [req.query.x as string];\n  a.map((v: string) => cp.exec(v));"),
    ("타입 표기 for-of", "취약",
     "  const a: string[] = req.body.list;\n  for (const v of a) { cp.exec(v); }\n"),
]


@pytest.mark.parametrize("name,want,body", CASES, ids=[c[0] for c in CASES])
def test_ts_idiom(tmp_path, name, want, body):
    f = tmp_path / "probe.ts"
    f.write_text(body[len(WHOLE):] if body.startswith(WHOLE) else TPL % body,
                 encoding="utf-8")
    hit = any(x.rule_id.startswith("js.") for x in scan_file(f, RULES))
    if want == "취약":
        assert hit, f"미탐: {name}"
    else:
        assert not hit, f"오탐: {name}"
