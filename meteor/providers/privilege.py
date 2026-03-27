import os

class PrivilegeProvider:
    """
    Detects if the tool is running as root.
    Gracefully handles modes (e.g., 'Combat Mode' vs 'User Mode').
    """

    @staticmethod
    def is_root() -> bool:
        """Returns True if the current user is root (UID 0), False otherwise."""
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False  # Non-Unix systems fallback

