"""
Log Analyzer module for identifying suspicious system behavior.
"""

import re
from typing import List, Dict
from ..providers.base import BaseProvider


class LogAnalyzer:
    """
    Analyzes system logs to discover anomalies such as failed logins.
    """
    def __init__(self, provider: BaseProvider):
        """
        Initialize LogAnalyzer with a specific OS provider.
        """
        self.provider = provider
        # Basic patterns for security event mapping
        self.suspicious_patterns = [
            re.compile(r'(?i)failed password'),
            re.compile(r'(?i)log cleared'),
            re.compile(r'(?i)unauthorized'),
            re.compile(r'(?i)session opened for user root')
        ]

    def analyze(self) -> List[Dict[str, str]]:
        """
        Retrieve logs using the OS provider and parse for suspicious patterns.
        """
        logs = self.provider.get_security_logs(limit=200)
        anomalies = []
        
        for line in logs:
            for pattern in self.suspicious_patterns:
                if pattern.search(line):
                    anomalies.append({
                        "pattern": pattern.pattern,
                        "log": line.strip()
                    })
                    break
                    
        return anomalies
