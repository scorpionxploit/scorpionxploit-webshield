"""
Tests for WebShield
"""
from webshield.scanner import WebShieldScanner

def test_score_full_security_headers():
    scanner = WebShieldScanner()
    headers = {
        "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
        "Content-Security-Policy": "default-src 'self';",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=()"
    }
    result = scanner.evaluate_headers(headers)
    assert result["score"] == 100
    assert result["grade"] == "A+"

def test_detect_missing_hsts():
    scanner = WebShieldScanner()
    headers = {
        "Content-Security-Policy": "default-src 'self';",
        "X-Frame-Options": "DENY"
    }
    result = scanner.evaluate_headers(headers)
    assert "strict-transport-security" in result["missing_headers"]
    assert result["score"] == 45
