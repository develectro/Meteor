"""
Abstract Base Provider for OS-specific tasks.
Ensures Open/Closed Principle for future OS expansions.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any


class BaseProvider(ABC):
    """
    Abstract interface for OS-specific operations like networking,
    process mapping, and log reading.
    """

    @abstractmethod
    def get_open_ports(self) -> List[Dict[str, Any]]:
        """
        Retrieve a list of currently open ports on the system.
        
        Returns:
            List[Dict[str, Any]]: A list of dictionaries detailing open port info.
        """
        pass

    @abstractmethod
    def get_process_for_port(self, port: int) -> Dict[str, Any]:
        """
        Map a specific open port to its owning process PID and executable path.
        
        Args:
            port (int): The port number to lookup.
            
        Returns:
            Dict[str, Any]: Dictionary containing 'pid' and 'exe_path'.
        """
        pass

    @abstractmethod
    def get_process_maps(self, pid: int) -> List[str]:
        """
        Retrieve memory maps for a specific process (e.g., from /proc/pid/maps).
        
        Args:
            pid (int): The process ID.
            
        Returns:
            List[str]: A list of memory map lines.
        """
        pass
