"""
Process Manager to map ports to process details.
"""

from typing import Dict, Any
from ..providers.base import BaseProvider


class ProcessManager:
    """
    Manages process-related mapping and tracking operations.
    """
    def __init__(self, provider: BaseProvider):
        """
        Initialize ProcessManager with a specific OS provider.
        """
        self.provider = provider

    def map_port_to_process(self, port: int) -> Dict[str, Any]:
        """
        Map a specific port to its process utilizing the OS provider.
        """
        return self.provider.get_process_for_port(port)
