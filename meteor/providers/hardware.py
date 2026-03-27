import os
from typing import Dict

class HardwareAudit:
    """Interfaces with /sys/devices/system/cpu/vulnerabilities/ to report CPU security status."""
    
    # Path to CPU vulnerabilities on Linux
    VULNERABILITIES_DIR = "/sys/devices/system/cpu/vulnerabilities/"
    
    @classmethod
    def check_vulnerabilities(cls) -> Dict[str, Dict[str, str]]:
        """
        Parses hardware vulnerabilities. Returns a dictionary with status and mitigation.
        """
        targets = ["meltdown", "spectre_v1", "spectre_v2", "spec_store_bypass", "l1tf", "mds"]
        results = {}
        
        for target in targets:
            filepath = os.path.join(cls.VULNERABILITIES_DIR, target)
            if os.path.exists(filepath):
                with open(filepath, "r") as f:
                    content = f.read().strip()
                
                if content == "Not affected":
                    status = "Safe"
                    mitigation = "None Required"
                elif content.startswith("Mitigation:"):
                    status = "Mitigated"
                    mitigation = content.split("Mitigation:", 1)[1].strip()
                elif content.startswith("Vulnerable"):
                    status = "Vulnerable"
                    mitigation = "None"
                else:
                    status = "Unknown"
                    mitigation = content
            else:
                status = "Unknown"
                mitigation = "File not found"
            
            results[target] = {"Status": status, "Mitigation": mitigation}
            
        return results
