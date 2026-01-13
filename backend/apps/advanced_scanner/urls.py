"""
URL configuration for advanced scanner app.
"""
from django.urls import path
from .views import AdvancedScanView, IndividualScanView

urlpatterns = [
    path('', AdvancedScanView.as_view(), name='advanced-scan'),
    path('<str:test_name>/', IndividualScanView.as_view(), name='individual-scan'),
]
