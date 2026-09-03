# 네이티브(WebView2) 다운로드 버그 2건 — 원인·수정

VM 클린 설치본에서 현장 테스트 중 발견. 둘 다 네이티브 데스크톱 창(pywebview + WebView2)
에서만 재현되고, 브라우저(`cpguard serve`)에서는 드러나지 않았다.

## 1) 잘못된 프로젝트 산출물이 다운로드됨 (분석목록표 등)

**증상.** DVWA(현재 프로젝트) 작업대에서 분석목록표(xlsx)를 내려받았는데, 이전에 스캔했던
다른 프로젝트(DVWA-mobile)의 목록표가 나왔다.

**원인.** 서버 export 로직은 전부 `pk` 스코프로 정확했다. 문제는 두 요소의 조합이다.
- **SQLite 는 삭제된 `pk`(rowid)를 재사용**한다 (`AUTOINCREMENT` 미사용, Django 기본).
- **WebView2 가 `GET /scan/<pk>/export.*` 응답을 디스크 캐시**한다 (동적 산출물인데
  캐시 금지 헤더가 없었음).

재현 흐름:
1. `DVWA-mobile` 스캔이 `pk=1` → 분석목록표 다운로드 → WebView2 가 그 URL 응답을 캐시
2. 해당 스캔 삭제(또는 DB 초기화) → `DVWA-master` 스캔이 **`pk=1` 을 재획득**
3. 분석목록표 클릭 → 동일 URL `/scan/1/export.xlsx` → WebView2 가 **캐시된 mobile 파일**을 반환

**수정.** 다운로드 뷰 5종(xlsx·csv·sarif·진단보고서 PDF·조치가이드 PDF)에
`@never_cache` 적용 → `Cache-Control: no-store`. 동적 산출물은 절대 캐시되지 않는다.
`cpguard/web/views.py`.

**잔여 위험.** 수정 *이전에* WebView2 가 캐시해 둔 항목은 남아 있을 수 있다. 재설치 후에도
같은 증상이면 새 스캔(새 pk)으로 확인하거나 WebView2 캐시를 비운다. 필요 시 다운로드 URL 에
스캔 타임스탬프를 붙여 pk 충돌 자체를 제거하는 방식으로 더 강하게 막을 수 있다.

## 2) PDF 리포트가 창을 뷰어로 탈취 → 앱 먹통

**증상.** PDF 리포트를 내려받으려 하면 데스크톱 창 전체가 WebView2 내장 PDF 뷰어로
바뀌어 버려, 앱 UI 로 돌아오지 못하고 아무 조작도 못 하게 된다.

**원인.** 산출 응답에 `Content-Disposition: attachment` 를 줬는데도, WebView2 내장 PDF
뷰어는 PDF content-type 으로의 **최상위 프레임 내비게이션**을 가로채 인라인 렌더한다.
xlsx/csv 는 인라인 뷰어가 없어 정상 다운로드됐고, PDF 만 창을 통째로 가져갔다.

**수정.** 모든 다운로드 링크(`<a>`)에 **`download` 속성**을 추가. Chromium/WebView2 는
`download` 속성이 있으면 내비게이션·인라인 렌더 대신 다운로드 경로로 보낸다
(`ALLOW_DOWNLOADS=True` 와 함께 동작). 작업대·리포트·프로젝트 홈 템플릿 전부 적용.

## 검증
- 회귀 테스트 추가: 다운로드 5종이 `Cache-Control: no-store` 인지, 작업대 HTML 의 다운로드
  링크에 `download` 속성이 있는지 확인. `tests/test_web.py`.
- web 스위트 23개 통과. 번들·설치본 재빌드해 VM 재테스트.

## 배운 점
네이티브 WebView 는 브라우저와 캐시·다운로드·인라인 뷰어 동작이 다르다. 동적 산출물은
(1) 캐시 금지 헤더, (2) 다운로드 링크에 `download` 속성 — 둘 다 명시해야 네이티브에서
브라우저와 동일하게 동작한다.
