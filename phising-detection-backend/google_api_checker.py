import re
from urllib.parse import urlparse
import requests

# Suspicious keywords & TLDs
SUSPICIOUS_KEYWORDS_DOMAIN = ['free', 'money', 'claim', 'bonus', 'win', 'prize', 'offer', 'evil']
SUSPICIOUS_TLDS = ['.ru', '.tk', '.cn', '.info', '.biz']
SUSPICIOUS_KEYWORDS_URL = ['login', 'secure', 'verify', 'update', 'account', 'bank', 'paypal']

# Trusted domains for homoglyph detection (lowercase)
TRUSTED_DOMAINS = ['google.com', 'paypal.com', 'facebook.com']

def contains_homoglyph(domain, trusted_domains):
    # Map common homoglyphs to their trusted chars
    homoglyph_map = {'0': 'o', '1': 'l', '3': 'e', '5': 's', '7': 't'}
    normalized = ''.join(homoglyph_map.get(c, c) for c in domain)

    # Check if normalized domain exactly matches any trusted domain
    # Avoid false positives if domain is exactly trusted domain
    if domain in trusted_domains:
        return False

    return normalized in trusted_domains

def heuristic_check(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    reasons = []

    # Remove port if present (e.g., example.com:8080)
    domain = domain.split(':')[0]

    # Rule 1: Suspicious keyword in domain as whole word or substring (avoid matching 'google' in 'googledomain')
    if any(keyword in domain for keyword in SUSPICIOUS_KEYWORDS_DOMAIN):
        reasons.append("Suspicious keyword in domain")

    # Rule 2: Suspicious TLD check — match only the end of domain
    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        reasons.append("Suspicious TLD")

    # Rule 3: IP address usage
    if is_ip_address(url):
        reasons.append("Contains IP address instead of domain")

    # Rule 4: Suspicious keywords in full URL
    if has_suspicious_keywords(url):
        reasons.append("Suspicious keywords detected in URL")

    # Rule 5: URL length check
    if is_too_long(url):
        reasons.append("URL length unusually long")

    # Rule 6: Homoglyph detection (check only if domain not in trusted domains)
    if contains_homoglyph(domain, TRUSTED_DOMAINS):
        reasons.append("Possible homoglyph/typosquatting detected")

    if reasons:
        return False, reasons

    return True, []

def is_ip_address(url):
    ip_pattern = r'https?://(\d{1,3}\.){3}\d{1,3}'
    return re.match(ip_pattern, url) is not None

def has_suspicious_keywords(url):
    url_lower = url.lower()
    return any(keyword in url_lower for keyword in SUSPICIOUS_KEYWORDS_URL)

def is_too_long(url, max_length=75):
    return len(url) > max_length

def check_url_safety(url):
    is_safe, reasons = heuristic_check(url)
    if not is_safe:
        return {
            "url": url,
            "is_safe": False,
            "threat_types": reasons,
            "message": "Heuristic rules triggered"
        }

    # Google Safe Browsing API (optional, you must add your own API key)
    google_api_key = "YOUR_GOOGLE_API_KEY"  # Replace with your real key
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={google_api_key}"

    body = {
        "client": {"clientId": "yourcompanyname", "clientVersion": "1.5.2"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(safe_browsing_url, json=body, timeout=10)
        data = response.json()
        if "matches" in data:
            threat_types = [match["threatType"] for match in data["matches"]]
            return {
                "url": url,
                "is_safe": False,
                "threat_types": threat_types,
                "message": "Detected by Google Safe Browsing API."
            }
        else:
            return {
                "url": url,
                "is_safe": True,
                "threat_types": [],
                "message": "No threats detected."
            }
    except requests.RequestException as e:
        return {
            "url": url,
            "is_safe": False,
            "threat_types": [],
            "message": f"Error checking URL safety: {str(e)}"
        }

def get_page_title(url):
    return "Page title unavailable"


# --- Example Usage ---
if __name__ == "__main__":
    test_urls = [
        "http://google.com",
        "http://faceb00k-verification.net",
        "http://app1e-support.com",
        "http://free-money-claim.ru",
        "https://paypal.com"
    ]

    for url in test_urls:
        result = check_url_safety(url)
        print(f"{url} -> Safe: {result['is_safe']} | Reasons: {result['threat_types']} | Msg: {result['message']}")
