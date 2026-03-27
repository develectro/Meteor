class KillChainAnalyzer:
    """
    Correlation engine combining:
    Local Port Status + Process Signature + System Log Anomalies + Hardware Vulnerabilities.
    Output a 'Global Risk Score' (0-100%).
    """
    
    def __init__(self, provider, scanner_results, log_anomalies, hardware_audit, threat_intel=None, root_mode=False):
        self.provider = provider
        self.scanner_results = scanner_results
        self.log_anomalies = log_anomalies
        self.hardware_audit = hardware_audit
        self.threat_intel = threat_intel or {}
        self.root_mode = root_mode

    def analyze(self) -> dict:
        score = 0
        reasons = []

        # 1. Hardware Risk
        for key, details in self.hardware_audit.items():
            if details.get('Status') == 'Vulnerable':
                score += 15
                reasons.append(f"Hardware vulnerable to {key}.")

        # 2. Scanner & Process Risk
        for res in self.scanner_results:
            risk = res.get('risk_level', 'Green')
            proc = res.get('process', {}).get('name', 'Unknown')
            port = res.get('port', 0)
            
            if risk == 'Red':
                score += 25
                reasons.append(f"High risk process '{proc}' detected on port {port}.")
            elif risk == 'Yellow':
                score += 10
                reasons.append(f"Suspicious process '{proc}' detected on port {port}.")

        # 3. Log Anomalies
        for anom in self.log_anomalies:
            score += 15
            reasons.append(f"Log anomaly: {anom.get('pattern')}.")

        # 4. External Threat Intel (AbuseIPDB, OTX, etc.)
        abuse_score = self.threat_intel.get('abuse_score', 0)
        if abuse_score > 50:
            score += 20
            reasons.append(f"External IP reputation is poor (Abuse Score: {abuse_score}%).")
        elif abuse_score > 10:
            score += 5
            reasons.append(f"External IP has minor abuse reports.")

        # 5. VirusTotal Logic (if applicable)
        vt_malicious = self.threat_intel.get('vt_malicious', 0)
        if vt_malicious > 0:
            score += 30
            reasons.append(f"Local process executable hash marked as MALICIOUS by {vt_malicious} engines on VirusTotal!")

        return {
            "score": min(score, 100),
            "reasons": reasons
        }

