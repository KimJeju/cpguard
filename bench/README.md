# 탐지 성능 벤치마크 (DVWA)

CPGuard 의 데이터 흐름(taint) 탐지 정확도를 **라벨링된 정답지**로 측정한다. 과장 없이,
방법론과 한계를 그대로 공개하는 것이 목적이다.

## 방법론

[DVWA](https://github.com/digininja/DVWA) 는 취약점 모듈마다 보안 수준별 소스를 제공한다.

- `vulnerabilities/<모듈>/source/low.php` — 의도적으로 **취약**(탐지해야 정답)
- `vulnerabilities/<모듈>/source/impossible.php` — 제대로 **방어**(탐지하면 오탐)

이 쌍이 ground truth 역할을 하므로 재현율·정밀도를 실제 수치로 잴 수 있다.

**정직성을 위한 두 가지 규칙:**
1. **측정 대상 = 해당 조각 안에 그 취약 유형의 sink 가 있는 모듈만.** DVWA `source/*.php` 는
   발췌 조각이라 출력(`echo`)·`include` 가 부모 페이지에 있는 경우가 많다. 조각 안에 sink 가
   없으면 *어떤* per-file 데이터흐름 분석기도 원리상 탐지할 수 없으므로 제외한다.
   (예: `xss_r/low.php` 는 `$html .= $_GET['name']` 뿐이고 `echo` 는 부모에 있음 → 제외)
2. **판정은 그 모듈이 목표하는 규칙(taint)만으로.** 다른 축(패턴·hygiene) 규칙이 `impossible.php`
   에서 발화하는 건 taint 엔진의 오탐이 아니므로(위험 API 사용 자체를 알리는 별개 축) 제외한다.

`medium/high` 는 부분 방어(우회 가능)라 정답이 모호해 지표에서 제외하고 참고로만 센다.

## 재현

```bash
python bench/dvwa_eval.py /path/to/DVWA --json bench/dvwa_result.json
```

## 결과 (DVWA-master, PHP, per-file)

| 지표 | 값 |
|---|---|
| 측정 대상 모듈 | 4 (exec · open_redirect · sqli · sqli_blind) |
| **재현율 (Recall)** | **100%** (4/4 취약 탐지) |
| **정밀도 (Precision)** | **80%** (탐지 중 실제 취약 비율) |
| **F1** | **0.889** |
| 오탐 | 1건 (`exec/impossible.php`) |

**유일한 오탐**은 `exec/impossible.php` 로, IP 옥텟을 `is_numeric` 으로 검증한 뒤 재조립해
`shell_exec` 에 넣는다. 현재 엔진은 이 검증 패턴을 sanitizer 로 인식하지 못해 흐름을 살아있는
것으로 본다 — **입력 검증 함수 인식**은 알려진 개선 과제다.

## 한계 (정직하게)

- **표본이 작다(N=4).** DVWA 조각 구조상 per-file 로 측정 가능한 데이터흐름 모듈이 적다.
  수치는 방향성 참고용이며, 더 큰 라벨 세트(OWASP Benchmark 등, 단 Java 는 미지원)가 필요하다.
- **per-file 측정**이라 파일 경계를 넘는 실제 강점은 과소평가된다. 전체 프로젝트 스캔에서는
  DVWA 앱 전반에 걸쳐 `php.sqli`·`php.command-injection`·`php.xss`·`php.ssrf` 등 248건을 탐지한다
  (부모-자식 파일을 잇는 프로시저간 분석 포함).
- 로드맵: sanitizer/검증 함수 인식 강화, 프레임워크 인지, 언어 확장(Java/Kotlin·C#·Go).
