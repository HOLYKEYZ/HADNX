"""
URL routing for scanner app.
"""
from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanViewSet, RepeaterView, ScriptRunnerView, NucleiScanView, SQLMapScanView, NmapScanView, ZapScanView, WiresharkView, ShannonViewSet, DoSViewSet

router = DefaultRouter()
router.register(r'shannon', ShannonViewSet, basename='shannon')
router.register(r'dos', DoSViewSet, basename='dos')
router.register(r'', ScanViewSet, basename='scan')

urlpatterns = [
    path('repeater/', RepeaterView.as_view(), name='repeater'),
    path('script-runner/', ScriptRunnerView.as_view(), name='script-runner'),
    path('nuclei/', NucleiScanView.as_view(), name='nuclei'),
    path('sqlmap/', SQLMapScanView.as_view(), name='sqlmap'),
    path('nmap/', NmapScanView.as_view(), name='nmap'),
    path('zap/', ZapScanView.as_view(), name='zap'),
    path('wireshark/', WiresharkView.as_view(), name='wireshark'),
] + router.urls
