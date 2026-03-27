"""
Heuristic Engine for correlating gathered system data.
"""

from typing import List, Dict, Any
from .scanner import ScannerEngine
from .process import ProcessManager

class HeuristicEngine:
    """
    Correlates open ports, processes, and potential risks to identify 
    suspicious endpoints (e.g. potential trojans).
    """
    def __init__(self, scanner: ScannerEngine, process_manager: ProcessManager):
        """
        Initialize HeuristicEngine with a scanner and process manager.
        """
        self.scanner = scanner
        self.process_manager = process_manager

    def evaluate_system_risk(self) -> List[Dict[str, Any]]:
        """
        Evaluate currently open ports against running processes to detect anomalies.
        """
        open_ports = self.scanner.scan_local_ports()
        risks = []

        for port_info in open_ports:
            port = port_info['port']
            proc_info = self.process_manager.map_port_to_process(port)
            
            # Simple heuristic example: process with unknown or missing executable path
            risk_level = "Green"
            reasons = []

            if not proc_info or not proc_info.get('pid'):
                risk_level = "Yellow"
                reasons.append(f"Port {port} is open but PID mapping failed.")
            elif proc_info.get('exe_path') in ['Access Denied / Not Found', 'Access Denied']:
                risk_level = "Red"
                reasons.append("Access denied fetching executable path.")
            elif proc_info.get('exe_path') == '':
                risk_level = "Yellow"
                reasons.append("Empty executable path detected.")
                
            port_info['process'] = proc_info
            port_info['risk_level'] = risk_level
            port_info['reasons'] = reasons
            risks.append(port_info)
            
        return risks
