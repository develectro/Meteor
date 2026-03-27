import math
import hashlib
import requests
from typing import Dict, Any, List

class PasswordAnalyzer:
    def __init__(self, password: str):
        self.password = password

    def analyze(self) -> Dict[str, Any]:
        """Analyzes password strength, crack time, and dictionary exposure."""
        pool_size = self._calculate_pool_size()
        length = len(self.password)
        entropy = length * math.log2(pool_size) if pool_size > 0 else 0
        combinations = pool_size ** length

        # Speeds: 
        # Normal CPU (e.g., single core MD5): 10^8 guesses/sec
        # Super GPU Cluster (e.g., 8x RTX 4090 MD5): 10^11 guesses/sec
        normal_cpu_speed = 10**8
        super_gpu_speed = 10**11

        time_normal = self._format_time(combinations / normal_cpu_speed)
        time_super = self._format_time(combinations / super_gpu_speed)

        pwned_count = self._check_pwned()
        
        # Strength categorization scoring (0 to 5)
        score = 0
        if length >= 8: score += 1
        if length >= 12: score += 1
        if pool_size >= 60: score += 1
        if entropy >= 60: score += 1
        if pwned_count == 0: score += 1

        if pwned_count > 0:
            score = min(score, 2) # Cap score heavily if compromised

        if score <= 2:
            strength = "Weak"
            color = "red"
        elif score <= 4:
            strength = "Medium"
            color = "yellow"
        else:
            strength = "Strong"
            color = "green"

        recommendations = self._get_recommendations(pool_size, length, pwned_count)

        return {
            "strength": strength,
            "color": color,
            "entropy": round(entropy, 2),
            "pwned": pwned_count > 0,
            "pwned_count": pwned_count,
            "time_normal": time_normal,
            "time_super": time_super,
            "recommendations": recommendations,
            "score_percent": max((score / 5) * 100, 5)  # Ensure minimum bar width
        }

    def _calculate_pool_size(self) -> int:
        pool = 0
        if any(c.islower() for c in self.password): pool += 26
        if any(c.isupper() for c in self.password): pool += 26
        if any(c.isdigit() for c in self.password): pool += 10
        if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?~` " for c in self.password): pool += 32
        return pool

    def _check_pwned(self) -> int:
        """Checks HIBP API using k-anonymity for dictionary/breach presence."""
        try:
            sha1_hash = hashlib.sha1(self.password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for h, count in hashes:
                    if h == suffix:
                        return int(count)
        except Exception:
            pass
        return 0

    def _format_time(self, seconds: float) -> str:
        if seconds < 1: return "Less than a second"
        minutes, seconds = divmod(seconds, 60)
        hours, minutes = divmod(minutes, 60)
        days, hours = divmod(hours, 24)
        years, days = divmod(days, 365)
        
        if years > 1e6: return "Millions of years"
        if years > 1000: return f"{int(years):,} years"
        if years > 0: return f"{int(years)} years, {int(days)} days"
        if days > 0: return f"{int(days)} days, {int(hours)} hours"
        if hours > 0: return f"{int(hours)} hours, {int(minutes)} mins"
        if minutes > 0: return f"{int(minutes)} mins, {int(seconds)} secs"
        return f"{int(seconds)} seconds"

    def _get_recommendations(self, pool_size: int, length: int, pwned_count: int) -> List[str]:
        recs = []
        if length < 12:
            recs.append("Increase length to at least 12 characters.")
        if pool_size < 60:
            recs.append("Mix uppercase, lowercase, numbers, and symbols.")
        if pwned_count > 0:
            recs.append(f"CRITICAL WARNING: Password found in {pwned_count} known data breaches/dictionaries! DO NOT USE IT.")
        if not recs:
            recs.append("Password looks excellent! Remember to avoid reusing it across platforms.")
        return recs
