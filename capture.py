import os
import requests
import json
import time
import threading
import pyshark

# Load API keys from environment variables
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GSB_API_KEY = os.getenv("GSB_API_KEY")

# Choose threat intelligence source
USE_GOOGLE_SAFE_BROWSING = True  # Set to False to use VirusTotal instead

# Stores visited sites and threat verification
visited_sites = {}

def check_virustotal(url):
    """Check URL reputation with VirusTotal"""
    vt_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VT_API_KEY, "Content-Type": "application/x-www-form-urlencoded"}
    data = {"url": url}
    
    response = requests.post(vt_url, headers=headers, data=data)
    if response.status_code == 200:
        result = response.json()
        return result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return None

def check_google_safe_browsing(url):
    """Check URL reputation with Google Safe Browsing"""
    gsb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"
    payload = {
        "client": {"clientId": "network-monitor", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(gsb_url, json=payload)
    if response.status_code == 200 and response.json():
        return "malicious"
    return "safe"

def analyze_url(url):
    """Check URL using VirusTotal or Google Safe Browsing"""
    if USE_GOOGLE_SAFE_BROWSING:
        return check_google_safe_browsing(url)
    return check_virustotal(url)

def capture_packets():
    """Capture packets and extract visited websites"""
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    interface_name = interfaces[0] if interfaces else "Wi-Fi"  # Default to Wi-Fi if no interfaces found
    cap = pyshark.LiveCapture(interface=interface_name, display_filter="http.request or tls.handshake.extensions_server_name")
    
    for packet in cap.sniff_continuously():
        try:
            if hasattr(packet, 'http'):
                url = packet.http.host
            elif hasattr(packet, 'tls'):
                url = packet.tls.handshake_extensions_server_name
            else:
                continue
            
            if url and url not in visited_sites:
                visited_sites[url] = analyze_url(url)
                print(f"{url}: {visited_sites[url]}")
        except Exception as e:
            print("Error processing packet:", e)

def start_capture():
    """Run capture in a separate thread"""
    thread = threading.Thread(target=capture_packets, daemon=True)
    thread.start()

start_capture()
