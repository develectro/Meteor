"""
Scanner Engine to handle port scanning operations.
"""

from typing import List, Dict, Any
from ..providers.base import BaseProvider


import os

class ScannerEngine:
    """
    Core engine responsible for port scanning operations, abstracted from the OS layer.
    """
    def __init__(self, provider: BaseProvider):
        """
        Initialize ScannerEngine with a specific OS provider.
        """
        self.provider = provider

    def scan_local_ports(self) -> List[Dict[str, Any]]:
        """
        Fetch local open ports using the provided OS implementation.
        """
        return self.provider.get_open_ports()

class DeepScanner:
    """
    Root-required Scanner with SYN Scanning and Process Integrity Checks.
    """
    def __init__(self, provider: BaseProvider):
        self.provider = provider

    def syn_scan(self, target: str, ports: List[int]) -> List[int]:
        """
        Performs a SYN scan against a target using raw sockets/scapy.
        """
        try:
            from scapy.all import sr1, IP, TCP
        except ImportError:
            return []
            
        open_ports = []
        for port in ports:
            packet = IP(dst=target)/TCP(dport=port, flags="S")
            response = sr1(packet, timeout=1, verbose=0)
            if response and response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12: # SYN-ACK
                    # Send RST to close the half-open connection
                    sr1(IP(dst=target)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                    open_ports.append(port)
        return open_ports

    def check_process_integrity(self, pid: int) -> bool:
        """
        Compare the running process in RAM with its disk executable and memory maps
        to detect Process Injection/Hollowing.
        """
        try:
            exe_link = f"/proc/{pid}/exe"
            if not os.path.exists(exe_link):
                return False
                
            exe_path = os.readlink(exe_link)
            if "(deleted)" in exe_path:
                return False
                
            # Advanced: Check memory maps for anonymous executable regions (Red flag for Hollowing/Injection)
            maps = self.provider.get_process_maps(pid)
            for line in maps:
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                permissions = parts[1]
                # If a region is executable ('x') and has no backing file (parts[5] is empty or not a path)
                if 'x' in permissions:
                    # Anonymous executable regions or executable stacks are highly suspicious
                    pathname = parts[5] if len(parts) > 5 else ""
                    if not pathname or pathname in ["[stack]", "[heap]", "[vdso]", "[vvar]"]:
                        # This process has executable code in a non-file-backed region
                        return False
            
            return True
        except (FileNotFoundError, PermissionError):
            return False
