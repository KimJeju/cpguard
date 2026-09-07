"""스캔 이력 저장."""
from __future__ import annotations

import json
from collections import Counter

from django.db import models

# 조치대상에서 빠지는 감사 상태. 합본 보고서(report/consolidated.AUDIT_REASON)와 같은
# 집합이어야 한다 — 어긋나면 화면과 제출 산출물의 건수가 달라진다(tests 가 감시한다).
CLOSED_AUDIT = ("false_positive", "deferred", "fixed")


class Scan(models.Model):
    name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    file_count = models.IntegerField(default=0)
    finding_count = models.IntegerField(default=0)
    findings_json = models.TextField(default="[]")
    sarif_json = models.TextField(default="{}")
    triage_note = models.CharField(max_length=500, blank=True, default="")
    integrity_note = models.CharField(max_length=500, blank=True, default="")
    # 탐지가 있는 파일의 원본 — 코드 뷰어가 흐름을 원문 위에 표시하려면 필요하다
    sources_json = models.TextField(default="{}")
    # 사람이 확정한 감사 결과 (finding 인덱스 -> 상태)
    audit_json = models.TextField(default="{}")
    # 감사자 의견 메모 (finding 인덱스 -> 평문 텍스트). HTML 렌더 안 함(표시 시 escape).
    audit_notes_json = models.TextField(default="{}")
    # 프로젝트 = 같은 대상의 스캔 묶음. 스캔 간 신규/해결 비교와 추세의 단위.
    project = models.CharField(max_length=255, blank=True, default="", db_index=True)
    new_count = models.IntegerField(default=0)        # 이전 스캔 대비 신규
    resolved_count = models.IntegerField(default=0)   # 이전 스캔에 있었으나 사라짐
    # 위험도별 카운트 비정규화 — 포트폴리오(수백 프로젝트) 목록이 findings_json 을
    # 역직렬화하지 않고 순수 DB 조회로 집계하도록. 저장 시 기록, 마이그레이션으로 백필.
    sev_critical = models.IntegerField(default=0)
    sev_high = models.IntegerField(default=0)
    sev_medium = models.IntegerField(default=0)
    sev_low = models.IntegerField(default=0)
    sev_info = models.IntegerField(default=0)
    # 진단 시 고른 점검 기준(쉼표 구분 id). 탐지 결과 자체는 기준과 무관하지만,
    # "무엇으로 진단하기로 했는가"가 남아야 산출물·검토 화면이 그 기준을 기본으로 쓴다.
    standards = models.CharField(max_length=120, blank=True, default="")
    # 진단 규모 근거 — 합본 보고서의 '빌드 라인 수 / 개발언어' 열이 쓴다.
    code_lines = models.IntegerField(default=0)
    languages = models.CharField(max_length=200, blank=True, default="")
    # 이 스캔에 실제로 적용된 설정 — 제외 경로·제외 규칙·적용 규칙 목록.
    # 보고서의 '제외 정보'·'분석 기준' 절이 이걸 그대로 싣는다(재현·감리 대응).
    scan_config_json = models.TextField(blank=True, default="{}")
    # 언어별 파일·라인·이슈·밀도 — 보고서 '분석 대상 현황'과 프로젝트 홈 카드
    stats_json = models.TextField(blank=True, default="{}")

    @property
    def language_list(self) -> list[str]:
        return [x for x in (self.languages or "").split(",") if x]

    @property
    def standard_ids(self) -> list[str]:
        """이 스캔에 지정된 기준 id 목록(모르는 값은 버린다)."""
        from .. import standards as _std
        return [s for s in (self.standards or "").split(",") if _std.get(s)]

    def store_severity_counts(self, counts: dict[str, int] | None = None) -> None:
        """위험도 카운트 컬럼을 채운다. counts 미지정 시 findings 에서 계산."""
        c = counts if counts is not None else self.severity_counts
        self.sev_critical = c.get("critical", 0)
        self.sev_high = c.get("high", 0)
        self.sev_medium = c.get("medium", 0)
        self.sev_low = c.get("low", 0)
        self.sev_info = c.get("info", 0)

    @property
    def sev_counts_fast(self) -> dict[str, int]:
        """역직렬화 없이 컬럼에서 읽는 위험도 카운트(포트폴리오·대시보드용)."""
        return {"critical": self.sev_critical, "high": self.sev_high, "medium": self.sev_medium,
                "low": self.sev_low, "info": self.sev_info}

    def previous(self):
        """같은 프로젝트의 직전 스캔."""
        if not self.project:
            return None
        return (Scan.objects.filter(project=self.project, created_at__lt=self.created_at)
                .order_by("-created_at").first())

    def compare_with(self, prev) -> dict:
        """지문(fp) 기준으로 신규/해결/유지 집합을 낸다. 줄 번호가 밀려도 같은 이슈로 본다."""
        cur = {f.get("fp"): f for f in self.findings if f.get("fp")}
        old = {f.get("fp"): f for f in (prev.findings if prev else []) if f.get("fp")}
        return {
            "new": [cur[k] for k in cur.keys() - old.keys()],
            "resolved": [old[k] for k in old.keys() - cur.keys()],
            "persistent": [cur[k] for k in cur.keys() & old.keys()],
            "new_fps": set(cur.keys() - old.keys()),
        }

    class Meta:
        ordering = ["-created_at"]

    @property
    def findings(self) -> list[dict]:
        fs = json.loads(self.findings_json)
        for i, f in enumerate(fs):
            f.setdefault("id", i)   # 구버전/외부 생성 스캔에 id 가 없어도 안전
        return fs

    @property
    def sources(self) -> dict[str, str]:
        return json.loads(self.sources_json)

    @property
    def audit(self) -> dict[str, str]:
        return json.loads(self.audit_json)

    def set_audit(self, index: int, status: str) -> None:
        a = self.audit
        if status:
            a[str(index)] = status
        else:
            a.pop(str(index), None)
        self.audit_json = json.dumps(a)
        self.save(update_fields=["audit_json"])

    @property
    def audit_notes(self) -> dict[str, str]:
        return json.loads(self.audit_notes_json)

    def set_audit_note(self, index: int, note: str) -> None:
        n = self.audit_notes
        note = (note or "").strip()
        if note:
            n[str(index)] = note[:4000]   # 과도한 길이 방지
        else:
            n.pop(str(index), None)
        self.audit_notes_json = json.dumps(n)
        self.save(update_fields=["audit_notes_json"])

    @property
    def language_stats(self) -> list[dict]:
        """언어별 통계를 이슈 많은 순으로. 화면·보고서가 그대로 표로 옮긴다."""
        try:
            by = (json.loads(self.stats_json or "{}") or {}).get("by_language") or {}
        except ValueError:
            return []
        rows = [{"language": k, **v} for k, v in by.items()]
        rows.sort(key=lambda r: (-r.get("issues", 0), -r.get("lines", 0)))
        return rows

    @property
    def scan_config(self) -> dict:
        try:
            return json.loads(self.scan_config_json or "{}")
        except ValueError:
            return {}

    @property
    def open_count(self) -> int:
        """조치대상 건수 — 오탐·보류·조치완료로 판정한 것을 뺀 나머지.

        탐지 총계(finding_count)는 스캔이 찾은 사실이라 감사로 바뀌지 않는다. 사람이
        판정하면서 줄어드는 것은 '앞으로 처리해야 할 것'이고, 합본 보고서의 최종
        조치대상과 같은 기준이어야 화면과 산출물의 숫자가 어긋나지 않는다."""
        a = self.audit
        return self.finding_count - sum(1 for v in a.values() if v in CLOSED_AUDIT)

    @property
    def open_severity_counts(self) -> dict[str, int]:
        """조치대상만 센 위험도 분포.

        인덱스 테이블(FindingRow)로 센다. 목록 화면은 행마다 이걸 부르는데, findings_json
        블롭을 파싱하면 5천 건짜리 스캔 하나가 목록 전체를 느리게 만든다. 인덱스가 없는
        옛 스캔만 블롭으로 되돌아간다."""
        closed = [int(k) for k, v in self.audit.items() if v in CLOSED_AUDIT]
        if self.finding_count and not self.rows.exists():
            a = self.audit                                    # 인덱스 이전에 만든 스캔
            return dict(Counter(f["severity"] for f in self.findings
                                if a.get(str(f["id"])) not in CLOSED_AUDIT))
        qs = self.rows.exclude(idx__in=closed) if closed else self.rows
        return {r["severity"]: r["n"] for r in
                qs.values("severity").annotate(n=models.Count("id"))}

    @property
    def audit_summary(self) -> dict[str, int]:
        """감사 상태별 건수. 미확인은 나머지 전부."""
        a = self.audit
        out = dict(Counter(v for v in a.values() if v))
        out["unaudited"] = self.finding_count - sum(out.values())
        return out

    @property
    def rule_counts(self) -> list[tuple[str, int]]:
        return Counter(f["rule_id"] for f in self.findings).most_common()

    @property
    def file_counts(self) -> list[tuple[str, int]]:
        return Counter(f["file"] for f in self.findings).most_common()

    @property
    def verdict_counts(self) -> dict[str, int]:
        # dict() 로 감싼다 — Django 템플릿은 {{ d.items }} 를 d["items"] 로 먼저 찾는데
        # Counter 는 없는 키에 0 을 돌려줘 {% for %} 가 int 를 순회하려 든다.
        return dict(Counter(v for f in self.findings if (v := f.get("verdict"))))

    @property
    def severity_counts(self) -> dict[str, int]:
        return dict(Counter(f["severity"] for f in self.findings))


class ReportTemplate(models.Model):
    """보고서 양식 — 발주처마다 요구가 다르고 사업별로 쌓인다.

    지금은 진단원이 Word 로 내려받아 매번 손으로 고쳤다. 어떤 절을 넣을지, 상세에
    소스와 의견을 실을지, 표지 제목과 로고를 무엇으로 할지를 저장해 두고 내보낼 때 고른다.
    """
    name = models.CharField(max_length=100, unique=True)
    title_override = models.CharField(max_length=200, blank=True, default="")
    header_note = models.CharField(max_length=300, blank=True, default="")   # 표지 아래 머리말
    logo_path = models.CharField(max_length=500, blank=True, default="")     # 로컬 이미지 경로
    references = models.CharField(max_length=200, blank=True, default="")    # 점검 기준 id, 쉼표
    include_detail = models.BooleanField(default=True)      # 4. 상세 결과
    include_source = models.BooleanField(default=True)      # 상세에 소스 스니펫
    include_comment = models.BooleanField(default=True)     # 상세에 진단원 의견
    include_exclusions = models.BooleanField(default=True)  # 부록 제외 정보
    include_rule_list = models.BooleanField(default=True)   # 부록 분석 기준
    include_scope = models.BooleanField(default=True)       # 부록 분석 대상 현황

    class Meta:
        ordering = ["name"]

    def as_dict(self) -> dict:
        return {
            "title_override": self.title_override, "header_note": self.header_note,
            "logo_path": self.logo_path,
            "include_detail": self.include_detail, "include_source": self.include_source,
            "include_comment": self.include_comment,
            "include_exclusions": self.include_exclusions,
            "include_rule_list": self.include_rule_list, "include_scope": self.include_scope,
        }

    @property
    def reference_list(self) -> list[str]:
        return [x.strip() for x in (self.references or "").split(",") if x.strip()]

    def __str__(self) -> str:
        return self.name


class AuditEvent(models.Model):
    """이슈 판정 변경 이력.

    합본 보고서의 '정오탐 점검' 단계가 곧 이 이력이다. 발주처 검수에서 "이 오탐 판정은
    누가 언제 했나"를 물으면 답할 근거가 있어야 한다. 1인 데스크톱이라 작성자는
    비워두고, 서버 에디션에서 사용자와 연결한다.
    """
    scan = models.ForeignKey("Scan", related_name="audit_events", on_delete=models.CASCADE)
    idx = models.IntegerField()                       # 스캔 내 finding id
    before = models.CharField(max_length=20, blank=True, default="")
    after = models.CharField(max_length=20, blank=True, default="")
    at = models.DateTimeField(auto_now_add=True)
    actor = models.CharField(max_length=100, blank=True, default="")
    bulk = models.BooleanField(default=False)         # 일괄 판정으로 바뀐 건인지

    class Meta:
        ordering = ["-at", "-id"]
        indexes = [models.Index(fields=["scan", "idx"])]


class ProjectSetting(models.Model):
    """프로젝트별 진단 설정 — 매 진단 반복되는 제외 작업을 저장해 둔다.

    테스트 코드·벤더 라이브러리·자동생성 코드를 빼는 건 사업마다 고정인데, 지금은
    진단원이 매번 손으로 걸러냈다. 제외 내역은 스캔에도 복사해 두어 보고서가
    "무엇을 왜 뺐는가"를 설명할 수 있게 한다.
    """
    project = models.CharField(max_length=200, unique=True)
    exclude_globs = models.TextField(blank=True, default="")   # 줄바꿈 구분 glob
    exclude_rules = models.TextField(blank=True, default="")   # 줄바꿈 구분 규칙 id
    note = models.TextField(blank=True, default="")            # 제외 사유(보고서에 실린다)

    @staticmethod
    def _lines(text: str) -> tuple[str, ...]:
        return tuple(x.strip() for x in (text or "").splitlines() if x.strip())

    @property
    def glob_list(self) -> tuple[str, ...]:
        return self._lines(self.exclude_globs)

    @property
    def rule_list(self) -> tuple[str, ...]:
        return self._lines(self.exclude_rules)

    def __str__(self) -> str:
        return self.project


class FindingRow(models.Model):
    """탐지 1건의 인덱스된 행 — 서버측 필터·정렬·집계·페이지네이션용(대량 탐지 대응).

    findings_json(전체 blob)과 별개로, 5만 건 규모에서도 O(page) 질의가 되도록
    스캔 생성 시 함께 적재한다. 상세 흐름/코드는 여전히 findings_json 에서 본다.
    """
    scan = models.ForeignKey(Scan, related_name="rows", on_delete=models.CASCADE)
    idx = models.IntegerField()                       # 스캔 내 finding id
    severity = models.CharField(max_length=12, db_index=True)
    rule_id = models.CharField(max_length=100, db_index=True)
    cwe = models.CharField(max_length=24, blank=True, default="")
    owasp = models.CharField(max_length=100, blank=True, default="")
    file = models.CharField(max_length=600, db_index=True)
    line = models.IntegerField(default=0)
    fp = models.CharField(max_length=40, blank=True, default="", db_index=True)
    category = models.CharField(max_length=20, blank=True, default="")
    verdict = models.CharField(max_length=20, blank=True, default="")
    message = models.TextField(blank=True, default="")

    class Meta:
        indexes = [
            models.Index(fields=["scan", "severity"]),
            models.Index(fields=["scan", "rule_id"]),
        ]
