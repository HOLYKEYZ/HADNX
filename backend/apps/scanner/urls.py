"""
URL routing for scanner app.
"""
from .views import ScanViewSet, RepeaterView, ScriptRunnerView

router = DefaultRouter()
router.register(r'', ScanViewSet, basename='scan')

urlpatterns = [
    path('repeater/', RepeaterView.as_view(), name='repeater'),
    path('script-runner/', ScriptRunnerView.as_view(), name='script-runner'),
] + router.urls
