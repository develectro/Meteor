# Chapter 4: The Intelligence Network 🌐

## External Spying (Intel Scrapers)
Meteor interacts with the world via the `meteor/external/` clients. These are designed to be "Spies" that fetch threat intelligence.

### 1. The Shodan Eye
Used to see the "External Attack Surface". If a port is open locally AND visible on Shodan, it increases the risk score drastically.

### 2. The VirusTotal Probe
Scans file hashes of running processes. If a process is detected as malicious by VT engines, Meteor flags it for immediate removal.

### 3. AbuseIPDB: The Reputation Guard
Checks the reputation of connected IPs. This is crucial for detecting C2 (Command & Control) callbacks.

### 4. BreachDirectory: Identity Guard
Performs live breach lookups for emails and social accounts. This module is vital for protecting the human element of **Spark Systems**.

---

## Technical Integration:
All external clients use the `EncryptedVault` for keys. They are designed to fail gracefully—if a key is missing, the engine continues with local data only.
