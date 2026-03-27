"""
Ubuntu-specific implementation of the BaseProvider.
"""

import os
import psutil
from typing import Dict, List, Any
from .base import BaseProvider


class UbuntuProvider(BaseProvider):
    """
    Provides Ubuntu-specific implementations for local scanning,
    process mapping, and log retrieval using psutil and checking /var/log/.
    """

    def get_open_ports(self) -> List[Dict[str, Any]]:
        """
        Retrieve a list of listening ports using psutil.
        """
        open_ports = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr:
                    open_ports.append({
                        'port': conn.laddr.port,
                        'protocol': 'TCP' if conn.type == 1 else 'UDP',
                        'local_address': conn.laddr.ip
                    })
        except psutil.AccessDenied:
            pass # Requires elevated privileges
            
        return open_ports

    def get_process_for_port(self, port: int) -> Dict[str, Any]:
        """
        Map an open port to its process ID and executable path using psutil.
        """
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.laddr.port == port:
                    pid = conn.pid
                    if pid:
                        try:
                            proc = psutil.Process(pid)
                            return {
                                'pid': pid,
                                'exe_path': proc.exe(),
                                'name': proc.name()
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            return {'pid': pid, 'exe_path': 'Access Denied / Not Found', 'name': 'Unknown'}
        except psutil.AccessDenied:
            return {'pid': None, 'exe_path': 'Access Denied', 'name': 'Unknown'}
            
        return {}

    def get_security_logs(self, limit: int = 100) -> List[str]:
        """
        Read /var/log/auth.log and /var/log/syslog for security events.
        """
        log_files = ['/var/log/auth.log', '/var/log/syslog']
        logs = []
        
        for log_file in log_files:
            if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        lines = f.readlines()
                        logs.extend(lines[-limit:])
                except Exception as e:
                    logs.append(f"Error reading {log_file}: {e}")
            else:
                logs.append(f"Cannot access {log_file}. Elevation might be required.")
                
        # Return the last `limit` lines overall
        return logs[-limit:]

    def get_process_maps(self, pid: int) -> List[str]:
        """
        Retrieve memory maps for a process from /proc/pid/maps.
        """
        maps_path = f"/proc/{pid}/maps"
        if os.path.exists(maps_path):
            try:
                with open(maps_path, 'r') as f:
                    return f.readlines()
            except (PermissionError, FileNotFoundError):
                pass
        return []
