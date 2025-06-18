from urllib.parse import urlparse
import re

def check_heuristics(url):
    parsed = urlparse(url)

    has_https = parsed.scheme == "https"
    has_ip = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", parsed.hostname or "") is not None
    suspicious_keywords = ["login", "verify", "secure", "update"]
    has_suspicious_keywords = any(word in url.lower() for word in suspicious_keywords)

    heuristics = {
        "has_https": has_https,
        "has_ip": has_ip,
        "has_suspicious_keywords": has_suspicious_keywords
    }

    # Phishing if 2 or more bad signs are present
    score = int(not has_https) + int(has_ip) + int(has_suspicious_keywords)
    is_phishing = score >= 2

    return is_phishing, heuristics
