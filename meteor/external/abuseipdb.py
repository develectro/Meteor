import requests
from typing import Dict, Any

class AbuseIPDBClient:
    """
    Client for interacting with the AbuseIPDB v2 API.
    """
    BASE_URL = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    def check_ip(self, ip_address: str, max_age_days: int = 90) -> Dict[str, Any]:
        """
        Check an IP address for abuse reports.
        """
        url = f"{self.BASE_URL}/check"
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': max_age_days
        }
        
        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"AbuseIPDB API Error: {response.status_code}", "status": "failed"}
        except Exception as e:
            return {"error": f"Request failed: {e}", "status": "failed"}
