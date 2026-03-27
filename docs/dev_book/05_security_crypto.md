# Chapter 5: The Cryptographic Shield 🔐

## 1. The Encrypted Vault
We store sensitive API keys in `~/.meteor_vault.json`, encrypted at rest.
- **KDF**: PBKDF2 with 600,000 iterations of SHA-256.
- **Encryption**: Fernet (AES-128-CBC + HMAC-SHA-256).
- **Security**: The Master Password is never stored. Only the derived key is kept in memory during runtime.

## 2. Privacy via K-Anonymity
When checking for breaches (HIBP/Password analysis), Meteor NEVER sends your full password or email hash to an external API.

### The Protocol:
1. Hash the secret (SHA-1). 
2. Send only the **First 5 characters** (the prefix).
3. The API returns all suffixes matching that prefix.
4. Meteor does the **Match Locally**.

> [!IMPORTANT]
> This ensures that **Spark Systems** tools are private by design. We don't just protect data; we protect the *presence* of data.
