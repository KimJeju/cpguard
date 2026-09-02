from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("scan/", views.upload, name="upload"),
    path("scan/<int:pk>/", views.detail, name="detail"),
    path("scan/<int:pk>/sarif/", views.sarif_download, name="sarif"),
    path("scan/<int:pk>/delete/", views.delete, name="delete"),
]
