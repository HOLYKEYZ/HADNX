"""
URL routing for scanner app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanViewSet, RepeaterView

router = DefaultRouter()
router.register(r'', ScanViewSet, basename='scan')

urlpatterns = [
    path('repeater/', RepeaterView.as_view(), name='repeater'),
] + router.urls
