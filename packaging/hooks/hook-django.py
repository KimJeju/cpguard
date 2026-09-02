"""PyInstaller 의 Django 훅 무력화.

기본 훅은 manage.py 기반 표준 프로젝트 레이아웃을 가정하고 앱 라벨을 최상위 모듈로
임포트하려 한다(우리 앱 라벨 'web' → `import web` 실패). CPGuard 는 Django 프로젝트를
패키지 안에 두므로, 필요한 모듈을 spec 에서 직접 지정하고 이 훅은 아무 것도 하지 않는다.
"""
hiddenimports = []
datas = []
