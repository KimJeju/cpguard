# CPGuard 배포본 빌드 (PowerShell)
#
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#
# 1) PyInstaller 로 실행 파일 번들 생성  -> dist\CPGuard\CPGuard.exe
# 2) Inno Setup 으로 설치 프로그램 생성  -> packaging\output\CPGuard-Setup-*.exe
#
# Inno Setup 이 없으면 1단계까지만 수행하고 설치 방법을 안내한다.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[1/2] PyInstaller 번들 생성..." -ForegroundColor Cyan
python -m PyInstaller packaging\cpguard.spec --noconfirm --distpath dist --workpath build\pyi
if ($LASTEXITCODE -ne 0) { throw "PyInstaller 빌드 실패" }

$exe = Join-Path $root "dist\CPGuard\CPGuard.exe"
if (-not (Test-Path $exe)) { throw "실행 파일이 생성되지 않았습니다: $exe" }
$size = [math]::Round((Get-ChildItem "dist\CPGuard" -Recurse | Measure-Object Length -Sum).Sum / 1MB, 1)
Write-Host "  완료: $exe ($size MB)" -ForegroundColor Green

# WebView2 런타임 설치기를 동봉한다 — 네이티브 창이 클린 머신에서도 뜨도록.
# 에어갭 배포는 오프라인 단독 설치기(MicrosoftEdgeWebView2RuntimeInstallerX64.exe)를
# 같은 폴더에 두면 그걸 우선 쓴다. 없으면 소용량 부트스트래퍼를 내려받는다(설치 시 온라인).
$redist = Join-Path $root "packaging\redist"
New-Item -ItemType Directory -Force -Path $redist | Out-Null
$wv2 = Join-Path $redist "MicrosoftEdgeWebView2Setup.exe"
$wv2Offline = Join-Path $redist "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
if (Test-Path $wv2Offline) {
    Copy-Item $wv2Offline $wv2 -Force
    Write-Host "  WebView2 오프라인 단독 설치기 사용(에어갭 대응)." -ForegroundColor Green
} elseif (-not (Test-Path $wv2)) {
    Write-Host "  WebView2 부트스트래퍼 내려받는 중..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri "https://go.microsoft.com/fwlink/p/?LinkId=2124703" -OutFile $wv2 -UseBasicParsing
        Write-Host "  완료: $wv2" -ForegroundColor Green
    } catch {
        Write-Host "  WebView2 설치기 다운로드 실패 — 설치본에 미동봉(런타임 없으면 브라우저 폴백으로 동작)." -ForegroundColor Yellow
    }
}

Write-Host "[2/2] Inno Setup 으로 설치 프로그램 생성..." -ForegroundColor Cyan
# winget 으로 설치하면 사용자 영역(LOCALAPPDATA)에 들어간다 - 그 경로도 함께 본다
$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "$env:LOCALAPPDATA\Programs\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $iscc) {
    Write-Host "  Inno Setup 이 없어 건너뜁니다." -ForegroundColor Yellow
    Write-Host "  설치: winget install -e --id JRSoftware.InnoSetup" -ForegroundColor Yellow
    Write-Host "  설치 후 이 스크립트를 다시 실행하면 install 파일이 만들어집니다." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "지금도 dist\CPGuard\CPGuard.exe 는 그대로 실행 가능합니다(무설치 이동식)." -ForegroundColor Green
    exit 0
}

& $iscc "packaging\cpguard.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup 빌드 실패" }

$setup = Get-ChildItem "packaging\output\CPGuard-Setup-*.exe" | Select-Object -First 1
Write-Host "  완료: $($setup.FullName)" -ForegroundColor Green
