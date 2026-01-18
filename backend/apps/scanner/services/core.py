import requests
import logging
import urllib3
from urllib.parse import urlparse

# Suppress InsecureRequestWarning for intentional verify=False usage
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

def fetch_url(url: str, timeout: int = 15):
    """
    Fetches a URL and returns response data including headers, cookies, and HTML.
    Handles redirects and SSL errors gracefully - this is a SECURITY SCANNER,
    so we intentionally scan sites with broken SSL.
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
    
    headers = {
        'User-Agent': 'Hadnx-Security-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    def _perform_request(target_url, verify_ssl=True):
        session = requests.Session()
        session.verify = verify_ssl
        return session.get(
            target_url, 
            timeout=timeout, 
            allow_redirects=True,
            headers=headers
        )

    try:
        # First try: Normal request with SSL verification
        response = _perform_request(url, verify_ssl=True)
    except requests.exceptions.SSLError as e:
        logger.warning(f"SSL Error for {url}: {e}")
        result['ssl_error'] = str(e)
        # Retry with verify=False
        try:
            response = _perform_request(url, verify_ssl=False)
            logger.info(f"Successfully fetched {url} with SSL verification disabled")
        except Exception as retry_e:
            result['error'] = f"SSL Error and Retry Failed: {str(retry_e)}"
            return result
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
        # Fallback: If HTTPS fails to connect/timeout, try HTTP
        if url.startswith("https://"):
            logger.warning(f"HTTPS failed ({type(e).__name__}) for {url}, falling back to HTTP")
            http_url = url.replace("https://", "http://", 1)
            try:
                response = _perform_request(http_url, verify_ssl=False)
                result['url'] = response.url # Update URL to indicate fallback
                logger.info(f"Successfully fetched {http_url} after fallback")
            except Exception as fallback_e:
                 logger.error(f"Fallback to HTTP also failed: {fallback_e}")
                 result['error'] = f"Connection Failed (HTTPS and HTTP): {str(e)}"
                 return result
        else:
            logger.error(f"Connection Error for {url}: {e}")
            result['error'] = f"Connection Error: {str(e)}"
            return result
    except requests.exceptions.RequestException as e:
        logger.error(f"Request Failed for {url}: {e}")
        result['error'] = str(e)
        return result

    # Process Successful Response (from any successful path above)
    try:
        result['status_code'] = response.status_code
        result['url'] = response.url
        result['headers'] = dict(response.headers)
        result['cookies'] = response.cookies.get_dict()
        result['html'] = response.text
        result['set_cookies'] = [c.name for c in response.cookies]
    except UnboundLocalError:
        # Should be covered by early returns, but safety check
        if not result['error']:
            result['error'] = "Unknown error: No response object"

    return result
