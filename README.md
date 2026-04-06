<div align="center">
  <h1>Meteor Security CLI</h1>
  <p><strong>Advanced Technical Diagnostics & Security Intelligence Monitoring</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Security_Engine-Advanced-E01E5A?style=for-the-badge" alt="Security Engine">
    <img src="https://img.shields.io/badge/Status-Operational-FFA500?style=for-the-badge" alt="Status">
    <img src="https://img.shields.io/badge/Environment-Linux%2FCLI-000000?style=for-the-badge" alt="Environment">
    <img src="https://img.shields.io/badge/License-MIT-000000?style=for-the-badge" alt="License">
  </p>

  <hr />

  <p>
    Meteor is a Python-based Command Line Interface (CLI) engineered for high-fidelity system diagnostics, network surveillance, and vulnerability detection. Built upon <strong>SOLID principles</strong> and a modular architecture, it provides security professionals with a robust framework for auditing local and external threat landscapes.
  </p>
</div>

## Core Features

1.  **Network Surveillance & Port Auditing**: High-performance monitoring of open TCP/UDP ports to identify active background listeners.
2.  **Process-to-Port Correlation**: Seamless mapping of open ports to active Process Identifiers (PID) and their executable paths.
3.  **Security Log Intelligence**: Continuous analysis of system authorization logs (e.g., `/var/log/auth.log`) to detect suspicious entry patterns and log-tampering attempts.
4.  **External Threat Intelligence (Shodan)**: Deep integration with the Shodan API to retrieve comprehensive risk reports for public-facing IP addresses.
5.  **Secure Credential Management (AES-256)**: An encrypted vault protected by PBKDF2-derived master passwords, ensuring sensitive API keys remain confidential.
6.  **Low-Level Hardware Diagnostics**: Direct inspection of CPU vulnerabilities including Spectre, Meltdown, and L1TF via kernel-level interfaces.
7.  **Data Breach & Exposure Analysis**: Identity guarding through K-Anonymity (SHA-1 hashing) to check for email exposure in global breach datasets without compromising privacy.
8.  **Global Threat Correlation Engine**: A centralized Kill Chain Analyzer that aggregates results from scanners, logs, and hardware audits to generate a composite Global Risk Score (0-100%).
9.  **Cryptographic Strength Evaluation**: Interactive password entropy analysis and crack-time estimation against modern high-speed GPU dictionaries.
10. **Privileged Deep Inspection (Combat Mode)**: Advanced functionality activated under Root privileges, enabling raw packet SYN scanning and process memory integrity checks.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/meteor.git
cd meteor

# 2. Initialize virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# 3. Install core dependencies and CLI
pip install -e .
```

---

## Usage

Once installed, the `meteor` command can be executed directly from your terminal:

```bash
# Execute local diagnostic scan (Ports & Security Patterns)
meteor scan

# Analyze authorization logs for suspicious activity
meteor logs

# Perform external IP threat assessment using Shodan
meteor shodan --key <YOUR_SHODAN_API_KEY> --ip <TARGET_IP>

# Generate a Comprehensive Intelligence Report
meteor full --key <YOUR_SHODAN_API_KEY> --ip <TARGET_IP>

# Manage Secure Vault (Add Encrypted API Credentials)
meteor vault add shodan

# Execute Hardware Vulnerability Audit
meteor hardware

# Verify Email Exposure in Known Data Breaches
meteor check-email user@example.com

# Execute Kill Chain Correlation Analysis
meteor killchain

# Evaluate Password Entropy & Cryptographic Vigor
meteor password
```

---

<div align="center">
  <h3>Advanced Deep Analysis (Combat Mode)</h3>
  <p>
    When executed with elevated privileges (<code>sudo</code>) on Linux systems, Meteor activates its high-intensity diagnostic engine:
  </p>
  <ul style="list-style: none;">
    <li><strong>Process Integrity Verification</strong>: Cross-referencing memory maps with disk-based binaries to detect Process Hollowing.</li>
    <li><strong>Advanced SYN Scanning</strong>: High-speed network reconnaissance utilizing raw TCP packet construction.</li>
  </ul>
  
  <p>
    <strong>Security Protocol</strong>: Accessing the encrypted vault or identity exposure checks requires the validation of the Master Password.
  </p>
  
  <p>
    <em>Note: Root privileges are recommended to ensure comprehensive access to protected process paths and authorization logs.</em>
  </p>
</div>

---

<<<<<<< HEAD
=======
## Architecture & Contributions
>>>>>>> 2d31342 (Added English Readem)

Meteor is designed for extensibility. The core engine utilizes the **Provider Pattern**, allowing for seamless integration of new audit layers (e.g., Windows or Cloud providers) without altering the primary analysis logic.

To contribute, please fork the repository and implement new providers within the `providers/` directory.

---

<div align="center">
  <p>© Spark Systems | Powered by Advanced Security Analytics</p>
</div>
