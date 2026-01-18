import requests
import sys

def check_site(url):
    print(f"Testing {url} ...")
    try:
        response = requests.get(url, timeout=10, verify=False)
        print(f"[OK] Success: {response.status_code}")
        print(f"     Final URL: {response.url}")
    except Exception as e:
        print(f"[FAIL] Failed: {type(e).__name__} - {str(e)}")

print("--- Network Diagnosis ---")
check_site("http://google.com")
check_site("http://testphp.vulnweb.com")
check_site("https://testphp.vulnweb.com")
