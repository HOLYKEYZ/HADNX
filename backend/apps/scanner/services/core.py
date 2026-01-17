import requests
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

def fetch_url(url: str, timeout: int = 15):
    """
    Fetches a URL and returns response data including headers, cookies, and HTML.
    Handles redirects and SSL errors gracefully.
    """
    result = {
        'url': url,
        'status_code': None,
        'headers': {},
        'cookies': {},
        'set_cookies': [],
        'html': '',
        'error': None,
        'ssl_error': None
    }
    
    try:
        # First try: Normal request with SSL verification
        response = requests.get(
            url, 
            timeout=timeout, 
            allow_redirects=True,
            headers={'User-Agent': 'Hadnx-Security-Scanner/1.0'}
        )
        
        result['status_code'] = response.status_code
        result['url'] = response.url # Capture final URL after redirects
        result['headers'] = dict(response.headers)
        result['cookies'] = response.cookies.get_dict()
        result['html'] = response.text
        
        # Capture Set-Cookie headers (requests merges them, so we need to access raw if possible, 
        # but requests.cookies is easier)
        # For simplicity, we use the cookie jar.
        result['set_cookies'] = [c.name for c in response.cookies] 

    except requests.exceptions.SSLError as e:
        logger.warning(f"SSL Error for {url}: {e}")
        result['ssl_error'] = str(e)
        
        # Retry without verification to at least analyze headers
        try:
            response = requests.get(
                url, 
                timeout=timeout, 
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Hadnx-Security-Scanner/1.0'}
            )
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            result['cookies'] = response.cookies.get_dict()
            result['html'] = response.text
            result['set_cookies'] = [c.name for c in response.cookies]
        except Exception as retry_e:
            result['error'] = f"SSL Failed and Retry Failed: {str(retry_e)}"

    except requests.exceptions.RequestException as e:
        logger.error(f"Request Failed for {url}: {e}")
        result['error'] = str(e)
        
    return result
