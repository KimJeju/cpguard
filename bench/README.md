# 탐지 성능 벤치마크

CPGuard 의 데이터 흐름(taint) 탐지 정확도를 **라벨링된 정답지**로 측정한다. 과장 없이,
방법론과 한계를 그대로 공개하는 것이 목적이다.

측정은 두 가지로 한다.

| 벤치마크 | 언어 | 표본 | 성격 |
|---|---|---|---|
| [OWASP Benchmark v1.2](#owasp-benchmark-v12-java) | Java | **1,572** | 대규모 합성 정답지 (주 지표) |
| [DVWA](#dvwa-php) | PHP | 4 | 실제 취약 앱, 표본 소규모 (보조) |

---

# OWASP Benchmark v1.2 (Java)

[OWASP Benchmark](https://owasp.org/www-project-benchmark/) 는 2,740 개의 Java 테스트케이스마다
"이 파일에 해당 취약점이 실제로 존재하는가"를 라벨링한 정답지를 제공한다. 같은 취약 유형에 대해
취약한 구현과 안전한 구현이 짝으로 들어 있어, 재현율뿐 아니라 **오탐률까지 규모 있게** 측정된다.

## 측정 범위

데이터 흐름(taint) 분석의 대상이 되는 6개 유형만 지표에 넣는다. `weakrand`·`crypto`·`hash`·
`securecookie` 는 "위험한 API 를 썼는가"를 보는 설정 점검 항목이고 `trustbound` 는 세션 속성의
신뢰 경계 문제라, taint 규칙의 대상이 아니다. 대상 밖 유형을 섞어 집계하면 수치가 왜곡되므로
**1,168건(crypto 246 · hash 236 · securecookie 67 · trustbound 126 · weakrand 493)은 제외**하고
그 사실을 함께 표기한다.

## 결과 (N = 1,572)

| 카테고리 | 대상 | TP | FN | FP | TN | 재현율 | 정밀도 | F1 | 오탐률 | 점수 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| cmdi | 251 | 87 | 39 | 75 | 50 | 69.0% | 53.7% | 0.604 | 60.0% | 0.090 |
| ldapi | 59 | 16 | 11 | 8 | 24 | 59.3% | 66.7% | 0.627 | 25.0% | 0.343 |
| pathtraver | 268 | 72 | 61 | 40 | 95 | 54.1% | 64.3% | 0.588 | 29.6% | 0.245 |
| sqli | 504 | 134 | 138 | 73 | 159 | 49.3% | 64.7% | 0.559 | 31.5% | 0.178 |
| xpathi | 35 | 9 | 6 | 11 | 9 | 60.0% | 45.0% | 0.514 | 55.0% | 0.050 |
| xss | 455 | 141 | 105 | 57 | 152 | 57.3% | 71.2% | 0.635 | 27.3% | 0.300 |
| **전체** | **1,572** | **459** | **360** | **264** | **489** | **56.0%** | **63.5%** | **0.595** | **35.1%** | **0.210** |

점수 = 재현율 − 오탐률 (OWASP Benchmark 공식 지표, 무작위 추측 = 0.000).

## 한계 (정직하게)

- **오탐의 지배적 원인은 경로 민감도 부재다.** Benchmark 의 안전 케이스 753건 중 **347건(46%)**
  이 `if ((7 * 42) - num > 200) bar = "상수"; else bar = param;` 처럼 **컴파일 시점에 결과가
  정해지는 조건**으로 취약 경로를 죽인다. CPGuard 는 분기 조건을 해석하지 않고 양쪽을 모두
  가능하다고 보므로(건전한 과대근사) 이런 케이스를 오탐으로 낸다.
  → **상수 전파(constant propagation)** 가 오탐률을 낮출 가장 큰 단일 지렛대다.
- **합성 벤치마크다.** 테스트케이스가 기계 생성이라 패턴이 반복되고, 실제 코드베이스의 분포와
  다르다. 특정 도구가 이 벤치마크에 과적합될 수 있다는 비판이 있으며 그 지적은 타당하다.
  그래서 실제 앱(DVWA) 측정을 함께 싣는다.
- **프레임워크 미인지.** Spring·JPA 등의 어노테이션 기반 진입점은 아직 소스로 인식하지 않는다.

## 재현

```bash
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git
python bench/owasp_benchmark.py BenchmarkJava --json bench/owasp_result.json
```

---

# DVWA (PHP)

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

## 결과 (DVWA-master, per-file)

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
  수치는 방향성 참고용이며, 규모 있는 지표는 위의 OWASP Benchmark(N=1,572)를 본다.
- **per-file 측정**이라 파일 경계를 넘는 실제 강점은 과소평가된다. 전체 프로젝트 스캔에서는
  DVWA 앱 전반에 걸쳐 `php.sqli`·`php.command-injection`·`php.xss`·`php.ssrf` 등 248건을 탐지한다
  (부모-자식 파일을 잇는 프로시저간 분석 포함).
- 로드맵: 상수 전파(경로 민감도), sanitizer/검증 함수 인식 강화, 프레임워크 인지.
