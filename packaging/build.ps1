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

Write-Host "[2/2] Inno Setup 으로 설치 프로그램 생성..." -ForegroundColor Cyan
$iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
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
