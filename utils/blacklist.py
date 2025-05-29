import requests
import os

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

def check_google_safe_browsing(url):
    if not GOOGLE_API_KEY:
        raise Exception("Google API Key not set. Please set GOOGLE_API_KEY in your .env file.")

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    payload = {
        "client": {
            "clientId": "phishing-detector",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    response = requests.post(api_url, json=payload)
    response.raise_for_status()  # Raise exception if request failed
    result = response.json()

    return bool(result.get("matches"))
