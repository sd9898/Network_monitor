import os
import requests

def check_url(url):
    """Check URL reputation with VirusTotal"""
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}
    data = {"url": url}

    try:
        response = requests.post(api_url, headers=headers, data=data)
        if response.status_code == 200:
            result = response.json()
            print(f"Checked {url}: {result}")
            return result
        else:
            print(f"Error checking {url}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Exception occurred while checking {url}: {e}")
    return None
