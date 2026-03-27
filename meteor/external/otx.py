import requests
from typing import Dict, Any, List

class OTXClient:
    """
    Client for interacting with the AlienVault OTX API.
    """
    BASE_URL = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json"
        }

    def check_indicator(self, indicator_type: str, indicator: str) -> Dict[str, Any]:
        """
        Check an indicator (IPv4, IPv6, domain, hostname, file hash).
        """
        # indicator_type: IPv4, IPv6, domain, hostname, file
        endpoint = f"{self.BASE_URL}/indicators/{indicator_type}/{indicator}/general"
        
        try:
            response = requests.get(endpoint, headers=self.headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"OTX API Error: {response.status_code}", "status": "failed"}
        except Exception as e:
            return {"error": f"Request failed: {e}", "status": "failed"}
