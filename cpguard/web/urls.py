from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("settings/", views.settings_page, name="settings"),
    path("compare/", views.compare, name="compare"),
    path("reports/", views.reports, name="reports"),
    path("project/<str:name>/", views.project_home, name="project_home"),
    path("scan/", views.upload, name="upload"),
    path("scan/progress/<str:job_id>/", views.scan_progress, name="scan_progress"),
    path("scan/progress/<str:job_id>/status", views.scan_status, name="scan_status"),
    path("scan/<int:pk>/", views.detail, name="detail"),
    path("scan/<int:pk>/sarif/", views.sarif_download, name="sarif"),
    path("scan/<int:pk>/delete/", views.delete, name="delete"),
    path("scan/<int:pk>/audit/", views.set_audit, name="set_audit"),
    path("scan/<int:pk>/note/", views.set_audit_note, name="set_audit_note"),
    path("scan/<int:pk>/ai/", views.ai_ask, name="ai_ask"),
    path("scan/<int:pk>/export.csv", views.export_csv, name="export_csv"),
    path("scan/<int:pk>/export.xlsx", views.export_xlsx, name="export_xlsx"),
    path("scan/<int:pk>/api/summary", views.scan_summary_api, name="scan_summary_api"),
    path("scan/<int:pk>/api/findings", views.scan_findings_api, name="scan_findings_api"),
    path("scan/<int:pk>/api/finding/<int:idx>", views.scan_finding_api, name="scan_finding_api"),
    path("scan/<int:pk>/report.pdf", views.export_pdf_report, name="export_pdf_report"),
    path("scan/<int:pk>/guide.pdf", views.export_pdf_guide, name="export_pdf_guide"),
]
