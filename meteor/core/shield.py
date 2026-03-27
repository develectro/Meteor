"""
Hardening Engine for Meteor Security CLI.
Provides system security scoring and automated mitigation suggestions.
"""

import os
from typing import List, Dict, Any

class HardeningEngine:
    """
    Analyzes system configuration and provides hardening recommendations.
    """
    
    def __init__(self):
        self.recommendations = []
        self.score = 100

    def audit_system(self) -> Dict[str, Any]:
        """Runs a suite of security configuration checks."""
        self.recommendations = []
        self.score = 100
        
        # 1. SSH Root Login
        self._check_ssh_root()
        
        # 2. ASLR (Address Space Layout Randomization)
        self._check_aslr()
        
        # 3. IP Spoofing Protection
        self._check_ip_spoofing()
        
        # 4. ICMP Redirects
        self._check_icmp_redirects()

        return {
            "score": self.score,
            "recommendations": self.recommendations
        }

    def _check_ssh_root(self):
        ssh_config = "/etc/ssh/sshd_config"
        if os.path.exists(ssh_config):
            try:
                with open(ssh_config, "r") as f:
                    content = f.read()
                    if "PermitRootLogin yes" in content:
                        self.score -= 20
                        self.recommendations.append({
                            "issue": "SSH Root Login is enabled",
                            "fix": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
                            "severity": "High"
                        })
            except PermissionError:
                pass

    def _check_aslr(self):
        aslr_path = "/proc/sys/kernel/randomize_va_space"
        if os.path.exists(aslr_path):
            with open(aslr_path, "r") as f:
                if f.read().strip() != "2":
                    self.score -= 30
                    self.recommendations.append({
                        "issue": "ASLR is not fully enabled",
                        "fix": "echo 2 > /proc/sys/kernel/randomize_va_space",
                        "severity": "Critical"
                    })

    def _check_ip_spoofing(self):
        # Reverse Path Filtering
        rp_filter = "/proc/sys/net/ipv4/conf/all/rp_filter"
        if os.path.exists(rp_filter):
            with open(rp_filter, "r") as f:
                if f.read().strip() == "0":
                    self.score -= 15
                    self.recommendations.append({
                        "issue": "IP Spoofing protection (RP Filter) is disabled",
                        "fix": "sysctl -w net.ipv4.conf.all.rp_filter=1",
                        "severity": "Medium"
                    })

    def _check_icmp_redirects(self):
        icmp_path = "/proc/sys/net/ipv4/conf/all/accept_redirects"
        if os.path.exists(icmp_path):
            with open(icmp_path, "r") as f:
                if f.read().strip() == "1":
                    self.score -= 10
                    self.recommendations.append({
                        "issue": "System accepts ICMP redirects (potential MITM)",
                        "fix": "sysctl -w net.ipv4.conf.all.accept_redirects=0",
                        "severity": "Low"
                    })
