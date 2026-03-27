import requests
from typing import Dict, Any

class VirusTotalClient:
    """
    Client for interacting with the VirusTotal v3 API.
    """
    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "x-apikey": self.api_key,
            "accept": "application/json"
        }

    def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Check a file hash (SHA-256, SHA-1, or MD5) against VirusTotal.
        """
        url = f"{self.BASE_URL}/files/{file_hash}"
        try:
            response = requests.get(url, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "Hash not found in VirusTotal.", "status": "clean"}
            else:
                return {"error": f"VirusTotal API Error: {response.status_code}", "status": "failed"}
        except Exception as e:
            return {"error": f"Request failed: {e}", "status": "failed"}

    def check_url(self, url_to_scan: str) -> Dict[str, Any]:
        """
        Scan a URL with VirusTotal.
        """
        # VT requires URLs to be base64 encoded without padding for the ID
        import base64
        url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
        endpoint = f"{self.BASE_URL}/urls/{url_id}"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"VirusTotal API Error: {response.status_code}", "status": "failed"}
        except Exception as e:
            return {"error": f"Request failed: {e}", "status": "failed"}
