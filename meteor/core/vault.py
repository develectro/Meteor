import json
import base64
import os
from typing import Optional, List
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

class EncryptedVault:
    """
    Encrypted API Vault to store keys for security services securely
    using Fernet (AES-256) and keys derived from PBKDF2.
    """
    
    VAULT_FILE = os.path.expanduser("~/.meteor_vault.json")
    SALT_FILE = os.path.expanduser("~/.meteor_salt")
    # Provider Registry
    REGISTERED_PROVIDERS = ["shodan", "breachdirectory", "hibp", "virustotal", "abuseipdb", "otx"]

    def __init__(self, master_password: str):
        self.key = self._derive_key(master_password)
        self.cipher = Fernet(base64.urlsafe_b64encode(self.key))
        self.data = self._load_vault()

    def _derive_key(self, password: str) -> bytes:
        if os.path.exists(self.SALT_FILE):
            with open(self.SALT_FILE, "rb") as f:
                salt = f.read()
        else:
            salt = os.urandom(16)
            with open(self.SALT_FILE, "wb") as f:
                f.write(salt)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,
        )
        return kdf.derive(password.encode())

    def _load_vault(self) -> dict:
        if os.path.exists(self.VAULT_FILE):
            with open(self.VAULT_FILE, "r") as f:
                try:
                    return json.load(f)
                except json.JSONDecodeError:
                    pass
        return {"providers": {}}

    def _save_vault(self):
        with open(self.VAULT_FILE, "w") as f:
            json.dump(self.data, f)

    def add_key(self, provider: str, api_key: str):
        if provider.lower() not in self.REGISTERED_PROVIDERS:
            raise ValueError(f"Provider '{provider}' is not in the registry. Supported: {self.REGISTERED_PROVIDERS}")
            
        encrypted_key = self.cipher.encrypt(api_key.encode()).decode('utf-8')
        if "providers" not in self.data:
            self.data["providers"] = {}
        self.data["providers"][provider.lower()] = encrypted_key
        self._save_vault()

    def get_key(self, provider: str) -> Optional[str]:
        encrypted_key = self.data.get("providers", {}).get(provider.lower())
        if not encrypted_key:
            return None
        try:
            return self.cipher.decrypt(encrypted_key.encode('utf-8')).decode('utf-8')
        except Exception:
            return None

    def get_configured_providers(self) -> List[str]:
        return list(self.data.get("providers", {}).keys())
