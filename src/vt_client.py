import os
import requests
from dotenv import load_dotenv

load_dotenv()

class VirusTotalClient:
    def __init__(self):
        self.api_key = os.getenv("VT_API_KEY")
        self.base_url = "https://www.virustotal.com/api/v3/urls"

    def check_url(self, url):
        if not self.api_key or self.api_key == "yahan_apni_wali_api_key_paste_karein":
            return {"error": "VirusTotal API key configure nahi ki gayi hai."}

        headers = {
            "x-apikey": self.api_key
        }
        
        # Pehle URL ko base64 encode karna padta hai VirusTotal v3 API ke liye
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        endpoint = f"{self.base_url}/{url_id}"
        
        try:
            response = requests.get(endpoint, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                return {
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "harmless": stats.get('harmless', 0),
                    "undetected": stats.get('undetected', 0)
                }
            elif response.status_code == 404:
                return {"error": "URL VirusTotal database mein nahi mila."}
            else:
                return {"error": f"API Error: Status code {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}