from django.urls import path
from . import views

urlpatterns = [
    path("", views.home, name="home"),
    path("phishing/", views.phishing_detector, name="phishing"),
    path("encrypt/", views.file_encryptor, name="encrypt"),
    path("scan/", views.port_scanner, name="scan"),
    path("scan/start/", views.start_scan, name="scan_start"),
    path("scan/status/<str:scan_id>/", views.scan_status, name="scan_status"),
]
