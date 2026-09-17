"""MCP 실증 루프 데모 — SAST 취약점을 동적으로 실증하는 한 바퀴.

실제 도구를 그대로 부른다(연출 아님): scan → evidence → probe → 실제 발사 → validation.
로컬 throwaway 취약 스크립트에 명령 주입을 실행하지만 페이로드는 지연(ping/sleep)이라
비파괴다. `pip install "cpguard[mcp]"` 후 `python examples/mcp_demo.py`.
"""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cpguard.mcp import tools

BAR = "─" * 66


def show(title, body):
    print(f"\n\033[1m{title}\033[0m" if sys.stdout.isatty() else f"\n{title}")
    print(body)


# 취약 대상 (인가된 로컬 throwaway) — 사용자 입력이 셸로 그대로 간다
VULN = (
    "import os\n"
    "user = os.environ.get('CMD_INPUT', '')   # source: 사용자 입력\n"
    "os.system('echo ' + user)                # sink: 셸 명령\n"
)
d = Path(tempfile.mkdtemp()); app = d / "handler.py"; app.write_text(VULN, encoding="utf-8")
store = tools.FindingStore()

print(BAR)
print("CPGuard MCP — SAST에서 찾은 취약점을 동적으로 실증하기")
print(BAR)

# 1) scan_file
scan = tools.scan_file(store, str(app))
fid = scan["findings"][0]["id"]
show("① scan_file  →  취약점 발견",
     f'   {scan["total"]}건 · {scan["counts"]}\n   {fid}')

# 2) finding.evidence — 왜 취약인가(source→sink)
ev = tools.finding_evidence(store, fid)
path = "\n".join(f'   {n["kind"]:11} L{n["line"]}  {n["code"]}' for n in ev["path"])
show("② finding.evidence  →  근거 (데이터 흐름)", path)

# 3) probe.get — 무엇을 넣고 무엇을 관찰하면 실증인가
p = tools.probe_get(store, fid)
show("③ probe.get  →  실증 탐침 + 오라클",
     f'   payload : {p["payload"]}   (shell: {p["payload_shell"]})\n'
     f'   oracle  : {p["oracle"]["type"]} — {p["oracle"]["expect"]}')

# 4) 에이전트가 발사(여기선 실제로 주입 실행) — 실제 지연 관찰
delay = 5
payload = f"& ping -n {delay+1} 127.0.0.1" if os.name == "nt" else f"; sleep {delay}"
t0 = time.time()
subprocess.run([sys.executable, str(app)], env={**os.environ, "CMD_INPUT": payload},
               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
elapsed = int((time.time() - t0) * 1000)
show("④ (에이전트가 자기 도구로 발사)  →  실제 주입 실행",
     f'   관찰: 응답 {elapsed}ms')

# 5) validation.submit — 오라클과 대조해 판정
v = tools.validation_submit(store, fid, {"elapsed_ms": elapsed})
show("⑤ validation.submit  →  판정",
     f'   \033[1;32m{v["verdict"]}\033[0m — {v["reason"]}'
     if sys.stdout.isatty() else f'   {v["verdict"]} — {v["reason"]}')

print(f"\n{BAR}")
print("정직 표기: 오라클 일치이지 IAST 아님 — '실제 실행 경로 확인'이 아니라")
print("           '예측한 관찰(5초+ 지연)이 나타났다'까지. 발사는 에이전트 몫.")
print(BAR)
