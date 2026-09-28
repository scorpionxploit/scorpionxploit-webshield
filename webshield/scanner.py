"""
ScorpionXploit WebShield - HTTP Security Header & TLS Inspector
Author: Aditya Sharma (scorpionxploit)
License: MIT
"""
from typing import Dict, Any, List

REQUIRED_HEADERS = {
    "strict-transport-security": {"weight": 25, "desc": "Enforces HTTPS connections"},
    "content-security-policy": {"weight": 30, "desc": "Mitigates XSS and data injection attacks"},
    "x-frame-options": {"weight": 15, "desc": "Prevents clickjacking attacks"},
    "x-content-type-options": {"weight": 10, "desc": "Prevents MIME-type sniffing"},
    "referrer-policy": {"weight": 10, "desc": "Controls referrer information leakage"},
    "permissions-policy": {"weight": 10, "desc": "Restricts browser feature access"}
}

class WebShieldScanner:
    def evaluate_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        normalized = {k.lower(): v for k, v in headers.items()}
        score = 0
        missing: List[str] = []
        present: List[str] = []

        for header_name, meta in REQUIRED_HEADERS.items():
            if header_name in normalized:
                score += meta["weight"]
                present.append(header_name)
            else:
                missing.append(header_name)

        grade = "F"
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 50:
            grade = "C"

        return {
            "score": score,
            "grade": grade,
            "present_headers": present,
            "missing_headers": missing
        }
