from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("scan/", views.upload, name="upload"),
    path("scan/<int:pk>/", views.detail, name="detail"),
    path("scan/<int:pk>/sarif/", views.sarif_download, name="sarif"),
    path("scan/<int:pk>/delete/", views.delete, name="delete"),
    path("scan/<int:pk>/audit/", views.set_audit, name="set_audit"),
    path("scan/<int:pk>/export.csv", views.export_csv, name="export_csv"),
]
