"""
Shodan API client for checking public host exposure.
"""

# Import shodan library, handle optional availability
try:
    import shodan
except ImportError:
    shodan = None


class ShodanClient:
    """
    Client for interacting with the Shodan API.
    """
    def __init__(self, api_key: str):
        """
        Initialize the ShodanClient with an API key.
        """
        self.api_key = api_key
        if shodan:
            self.api = shodan.Shodan(self.api_key)
        else:
            self.api = None

    def check_exposure(self, ip_address: str) -> dict:
        """
        Query Shodan to identify exposure of a given public IP.
        """
        if not self.api:
            return {"error": "shodan library not installed. Please run 'pip install shodan'."}
            
        try:
            results = self.api.host(ip_address)
            return results
        except shodan.APIError as e:
            return {"error": f"Shodan API Error: {e}"}
        except Exception as e:
            return {"error": f"Unknown error: {e}"}
