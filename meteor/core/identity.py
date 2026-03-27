import hashlib
from typing import Dict, Any

class IdentityGuard:
    """
    Breach Detection with SHA-1 hashing logic (K-Anonymity) for email privacy.
    Factory to switch between Breach APIs based on available keys in the Vault.
    """
    def __init__(self, vault):
        self.vault = vault

    def check_email_breach(self, email: str, provider: str = None) -> Dict[str, Any]:
        """Query vault for available providers, choose one, check breach."""
        # Clean email
        email = email.strip().lower()

        # k-anonymity SHA-1 hash for email privacy
        sha1_hash = hashlib.sha1(email.encode('utf-8')).hexdigest().upper()
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]

        providers = self.vault.get_configured_providers()
        if not providers:
            return {"error": "No providers configured in vault.", "status": "failed"}

        target_provider = provider if provider else providers[0]

        if target_provider == "hibp":
            return self._check_hibp(hash_prefix, hash_suffix)
        elif target_provider == "breachdirectory":
            api_key = self.vault.get_key("breachdirectory")
            return self._check_breachdirectory(email, api_key)
        else:
            return {"error": f"Provider {target_provider} not supported for email checks.", "status": "failed"}

    def _check_hibp(self, prefix: str, suffix: str) -> Dict[str, Any]:
        # Implementation of HIBP check (using K-Anonymity, simulation for email breach API)
        key = self.vault.get_key("hibp")
        if not key:
            return {"error": "HIBP key not found.", "status": "failed"}
        
        return {
            "status": "success", 
            "message": f"Simulated HIBP K-Anonymity Check Completed for Prefix: {prefix}. No breaches found.",
            "provider": "hibp"
        }

    def _check_breachdirectory(self, email: str, api_key: str) -> Dict[str, Any]:
        if not api_key:
            return {"error": "BreachDirectory key not found.", "status": "failed"}
        
        return {
            "status": "success",
            "message": f"Simulated BreachDirectory API Check for '{email}'. No breaches found.",
            "provider": "breachdirectory"
        }

