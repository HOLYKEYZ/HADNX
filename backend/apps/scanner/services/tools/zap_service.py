import logging
import time
from zapv2 import ZAPv2
from django.conf import settings

logger = logging.getLogger(__name__)

class ZapService:
    # Default ZAP API config
    # In production, these should be in settings/env
    ZAP_API_KEY = '' # Disable API key for local usage or set via env
    ZAP_PROXY_HOST = '127.0.0.1'
    ZAP_PROXY_PORT = '8080'

    @staticmethod
    def get_zap_client():
        """Returns a configured ZAPv2 client."""
        return ZAPv2(
            apikey=ZapService.ZAP_API_KEY,
            proxies={
                'http': f'http://{ZapService.ZAP_PROXY_HOST}:{ZapService.ZAP_PROXY_PORT}',
                'https': f'http://{ZapService.ZAP_PROXY_HOST}:{ZapService.ZAP_PROXY_PORT}'
            }
        )

    @staticmethod
    def check_connection():
        """Checks if ZAP is running and reachable."""
        try:
            zap = ZapService.get_zap_client()
            version = zap.core.version
            return {"connected": True, "version": version}
        except Exception as e:
            return {"connected": False, "error": str(e)}

    @staticmethod
    def spider_scan(target_url):
        """Starts a ZAP Spider scan on the target."""
        zap = ZapService.get_zap_client()
        try:
            logger.info(f"Starting ZAP Spider on {target_url}")
            scan_id = zap.spider.scan(url=target_url)
            return {"status": "started", "scan_id": scan_id, "type": "spider"}
        except Exception as e:
            logger.error(f"ZAP Spider Error: {e}")
            return {"error": str(e)}

    @staticmethod
    def active_scan(target_url):
        """Starts a ZAP Active Scan (Attack) on the target."""
        zap = ZapService.get_zap_client()
        try:
            logger.info(f"Starting ZAP Active Scan on {target_url}")
            scan_id = zap.ascan.scan(url=target_url)
            return {"status": "started", "scan_id": scan_id, "type": "active_scan"}
        except Exception as e:
            logger.error(f"ZAP Active Scan Error: {e}")
            return {"error": str(e)}

    @staticmethod
    def get_status(scan_id, scan_type="spider"):
        """Gets progress of a scan."""
        zap = ZapService.get_zap_client()
        try:
            if scan_type == "spider":
                progress = zap.spider.status(scan_id)
            else:
                progress = zap.ascan.status(scan_id)
            return {"status": "running" if int(progress) < 100 else "completed", "progress": progress}
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def get_alerts(target_url):
        """Retrieves findings (alerts) for the target."""
        zap = ZapService.get_zap_client()
        try:
            alerts = zap.core.alerts(baseurl=target_url)
            return {"alerts": alerts}
        except Exception as e:
            return {"error": str(e)}
