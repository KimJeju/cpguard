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

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\{cm:UninstallProgram,{#AppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 스캔 이력 DB 는 사용자 홈(~/.cpguard)에 있으므로 제거하지 않는다.
; 프로그램 폴더에 생긴 캐시만 정리한다.
Type: filesandordirs; Name: "{app}\_internal\__pycache__"
