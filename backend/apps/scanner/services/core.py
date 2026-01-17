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
    
    try:
        # First try: Normal request with SSL verification
        response = requests.get(
            url, 
            timeout=timeout, 
            allow_redirects=True,
            headers=headers
        )
        
        result['status_code'] = response.status_code
        result['url'] = response.url  # Capture final URL after redirects
        result['headers'] = dict(response.headers)
        result['cookies'] = response.cookies.get_dict()
        result['html'] = response.text
        result['set_cookies'] = [c.name for c in response.cookies]

    except requests.exceptions.SSLError as e:
        logger.warning(f"SSL Error for {url}: {e}")
        result['ssl_error'] = str(e)
        
        # Retry without SSL verification - this is a security scanner,
        # we WANT to analyze sites with broken SSL
        try:
            # Create a new session with SSL verification disabled
            session = requests.Session()
            session.verify = False
            
            response = session.get(
                url, 
                timeout=timeout, 
                allow_redirects=True,
                headers=headers
            )
            result['status_code'] = response.status_code
            result['url'] = response.url
            result['headers'] = dict(response.headers)
            result['cookies'] = response.cookies.get_dict()
            result['html'] = response.text
            result['set_cookies'] = [c.name for c in response.cookies]
            logger.info(f"Successfully fetched {url} with SSL verification disabled")
            
        except Exception as retry_e:
            logger.error(f"Retry without SSL also failed for {url}: {retry_e}")
            result['error'] = f"SSL Error and Retry Failed: {str(retry_e)}"

    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection Error for {url}: {e}")
        result['error'] = f"Connection Error: Could not connect to {url}"
        
    except requests.exceptions.Timeout as e:
        logger.error(f"Timeout for {url}: {e}")
        result['error'] = f"Timeout: The server took too long to respond"
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Request Failed for {url}: {e}")
        result['error'] = str(e)
        
    return result
