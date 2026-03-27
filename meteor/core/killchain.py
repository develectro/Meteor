class KillChainAnalyzer:
    """
    Correlation engine combining:
    Local Port Status + Process Signature + System Log Anomalies + Hardware Vulnerabilities.
    Output a 'Global Risk Score' (0-100%).
    """
    
    def __init__(self, provider, scanner_results, log_anomalies, hardware_audit, root_mode=False):
        self.provider = provider
        self.scanner_results = scanner_results
        self.log_anomalies = log_anomalies
        self.hardware_audit = hardware_audit
        self.root_mode = root_mode

    def analyze(self) -> dict:
        score = 0
        reasons = []

        # Hardware Risk: High vulnerabilities add to the score
        for key, details in self.hardware_audit.items():
            if details.get('Status') == 'Vulnerable':
                score += 15
                reasons.append(f"Hardware vulnerable to {key}.")

        # Scanner Risk
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

        # Log Anomalies
        for anom in self.log_anomalies:
            score += 15
            reasons.append(f"Log anomaly: {anom.get('pattern')}.")

        # Root Process Injection Checks
        if self.root_mode:
            # Add specific reasoning based on advanced correlations
            pass

        return {
            "score": min(score, 100),
            "reasons": reasons
        }

