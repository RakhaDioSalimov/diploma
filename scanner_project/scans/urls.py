from django.urls import path
from .views import scan_list, start_scan

urlpatterns = [
    path('', scan_list, name='scan_list'),
    path('start/', start_scan, name='start_scan'),
]