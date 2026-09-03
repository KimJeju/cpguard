; CPGuard 설치 프로그램 (Inno Setup)
;
; 빌드:  ISCC.exe packaging\cpguard.iss
; 산출:  packaging\output\CPGuard-Setup-<버전>.exe
;
; 전제: 먼저 PyInstaller 번들을 만들어야 한다.
;   pyinstaller packaging/cpguard.spec --noconfirm

#define AppName "CPGuard"
#define AppVersion "0.1.0"
#define AppPublisher "CPGuard"
#define AppURL "https://github.com/KimJeju/cpguard"
#define AppExeName "CPGuard.exe"
; 네이티브 창(pywebview)은 Edge WebView2 런타임을 요구한다. 클린/내부망 머신엔
; 없을 수 있으므로 설치본에 동봉해 전제조건으로 설치한다(있으면 건너뜀).
#define WV2Setup "redist\MicrosoftEdgeWebView2Setup.exe"
#define HasWV2 FileExists(AddBackslash(SourcePath) + WV2Setup)

[Setup]
AppId={{7F3B9C42-5E8A-4D21-9B6E-CPGUARD0001}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
; 관리자 권한 없이 사용자 영역에 설치 — 설치 마찰을 줄인다
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=output
OutputBaseFilename=CPGuard-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\{#AppExeName}

[Languages]
Name: "korean"; MessagesFile: "compiler:Languages\Korean.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; PyInstaller onedir 산출물 전체
Source: "..\dist\CPGuard\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\dist\CPGuard\_internal\*"; DestDir: "{app}\_internal"; Flags: ignoreversion recursesubdirs createallsubdirs
; 문서
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
#if HasWV2
; WebView2 런타임 설치기 — 런타임이 없을 때만 임시폴더로 풀어 실행한다
Source: "{#WV2Setup}"; DestDir: "{tmp}"; Flags: deleteafterinstall; Check: WebView2Missing
#endif

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
#if HasWV2
; 앱 실행보다 먼저: 런타임이 없으면 조용히 설치(관리자 없이도 per-user 설치됨)
Filename: "{tmp}\MicrosoftEdgeWebView2Setup.exe"; Parameters: "/silent /install"; StatusMsg: "Microsoft Edge WebView2 런타임 설치 중..."; Check: WebView2Missing; Flags: waituntilterminated
#endif
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[Code]
// WebView2(에버그린) 런타임 존재 여부 — per-machine(WOW6432Node) 과 per-user 키를 본다.
// 클라이언트 GUID {F3017226-...} 는 WebView2 런타임 고정값.
function WebView2Present(): Boolean;
var pv: String;
begin
  Result := False;
  if RegQueryStringValue(HKLM, 'SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', pv) then
    if (pv <> '') and (pv <> '0.0.0.0') then Result := True;
  if not Result then
    if RegQueryStringValue(HKCU, 'SOFTWARE\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}', 'pv', pv) then
      if (pv <> '') and (pv <> '0.0.0.0') then Result := True;
end;

function WebView2Missing(): Boolean;
begin
  Result := not WebView2Present();
end;

[UninstallDelete]
; 스캔 이력 DB 는 사용자 홈(~/.cpguard)에 있으므로 제거하지 않는다.
; 프로그램 폴더에 생긴 캐시만 정리한다.
Type: filesandordirs; Name: "{app}\_internal\__pycache__"
