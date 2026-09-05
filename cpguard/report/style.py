"""산출물 공통 팔레트 — 검은 글자 + 옅은 회색.

PDF·Word·xlsx 가 같은 표를 다른 포맷으로 낼 뿐이므로 색을 한 군데 둔다. 진단 보고서는
흑백 출력·복사본으로 돌아다니고 발주처 문서 양식에 그대로 얹히는 일이 많아, 색으로만
구분되는 정보를 두지 않는다. 위험도는 색상이 아니라 **명도**로 구분하고, 판정은 글자
자체(취약/양호/진단 대상 아님)로 읽히게 한다.
"""
from __future__ import annotations

INK = "#1a1a1a"          # 본문·제목
INK_SOFT = "#444444"     # 부제·보조 텍스트
MUTED = "#808080"        # 흐린 텍스트(진단 대상 아님 등)
FAINT = "#9a9a9a"

LINE = "#d0d0d0"         # 표 테두리
LINE_SOFT = "#e2e2e2"
FILL_HEAD = "#ededed"    # 표 머리글 배경
FILL_ZEBRA = "#f7f7f7"   # 강조 행 배경
FILL_BOX = "#f4f4f4"     # 코드 블록 배경

BAR = "#3a3a3a"          # 막대 그래프 채움
BAR_BG = "#eeeeee"

#: 위험도 — 색상이 아니라 명도로 구분한다(흑백 출력에서도 순서가 읽힌다).
SEV_INK = {"critical": "#2b2b2b", "high": "#4a4a4a", "medium": "#6e6e6e",
           "low": "#909090", "info": "#b0b0b0"}

#: 엑셀 셀 음영(ARGB 없이 RRGGBB). 같은 순서의 명도 단계.
SEV_FILL_XLSX = {"critical": "BFBFBF", "high": "D0D0D0", "medium": "E0E0E0",
                 "low": "EDEDED", "info": "F5F5F5"}
VIOLATED_FILL_XLSX = "D9D9D9"
