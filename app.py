##
from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import tldextract
import whois
from datetime import datetime
from urllib.parse import urlparse
import ssl
import socket

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# -------------------------------
# Simple cache for WHOIS lookups
# -------------------------------
WHOIS_CACHE = {}

def cached_whois(domain):
    if domain in WHOIS_CACHE:
        return WHOIS_CACHE[domain]
    try:
        data = whois.whois(domain)
    except Exception:
        data = None
    WHOIS_CACHE[domain] = data
    return data

# -------------------------------
# Analyzer: URL structure
# -------------------------------
def analyze_url_structure(url):
    issues, warnings, details = [], [], []
    score_impact = 0

    parsed_url = urlparse(url)
    host = parsed_url.hostname or ""

    # HTTPS check
    if parsed_url.scheme != "https":
        issues.append("Website does not use HTTPS")
        score_impact -= 20

    # IP address check
    ip_regex = r'^\d{1,3}(?:\.\d{1,3}){3}$'
    if re.match(ip_regex, host):
        issues.append("Uses raw IP address instead of domain")
        score_impact -= 20

    # Suspicious '@'
    if '@' in url and url.find('@') > url.find('//') + 2:
        issues.append("Contains '@' which can hide real destination")
        score_impact -= 15

    # Multiple subdomains
    if host.count('.') >= 3:
        warnings.append("Multiple subdomains detected")
        score_impact -= 10

    # Encoded characters
    if '%' in url and any(x in url.lower() for x in ['%2f', '%3f', '%3d', '%26']):
        issues.append("Contains encoded characters, may be obfuscation")
        score_impact -= 10

    # Brand check
    brands = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'bank', 'facebook', 'ebay']
    found = [b for b in brands if b in url.lower()]
    if found:
        ext = tldextract.extract(host)
        reg_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        if found[0] != ext.domain:
            issues.append(f'Brand "{found[0]}" found outside registered domain ({reg_domain})')
            score_impact -= 20

    # Long URL
    if len(url) > 75:
        warnings.append("URL unusually long")
        score_impact -= 5
    if len(url) > 200:
        warnings.append("URL very long (hides malicious params)")
        score_impact -= 10

    # Non-standard port
    if parsed_url.port and parsed_url.port not in (80, 443):
        warnings.append(f"Non-standard port used: {parsed_url.port}")
        score_impact -= 5

    return {
        "status": "danger" if issues else "warning" if warnings else "safe",
        "description": issues[0] if issues else warnings[0] if warnings else "Normal structure",
        "score_impact": score_impact,
        "details": issues + warnings
    }

# -------------------------------
# Analyzer: SSL
# -------------------------------
def analyze_ssl(url):
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            raise ValueError("Invalid hostname")

        context = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                cert = ssock.getpeercert()

        not_after = cert.get("notAfter")
        if not not_after:
            return {"status": "warning", "description": "SSL certificate has no expiry", "score_impact": 0}

        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        except Exception:
            return {"status": "warning", "description": "Could not parse SSL expiry", "score_impact": 0}

        if datetime.utcnow() > expires:
            return {"status": "danger", "description": "SSL certificate expired", "score_impact": -20}

        days_left = (expires - datetime.utcnow()).days
        if days_left < 30:
            return {"status": "warning", "description": f"SSL expiring soon ({days_left} days)", "score_impact": -5}

        return {"status": "safe", "description": "SSL valid", "score_impact": 0}

    except Exception:
        return {"status": "warning", "description": "SSL check failed", "score_impact": 0}

# -------------------------------
# Analyzer: Domain WHOIS
# -------------------------------
def analyze_domain(url):
    try:
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            raise ValueError("Invalid domain")

        info = cached_whois(domain)
        if not info or not info.creation_date:
            return {"status": "warning", "description": "WHOIS unavailable", "score_impact": 0}

        creation = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
        if not isinstance(creation, datetime):
            return {"status": "warning", "description": "WHOIS date invalid", "score_impact": 0}

        age_days = (datetime.utcnow() - creation).days
        if age_days < 30:
            return {"status": "danger", "description": f"Domain very new ({age_days} days)", "score_impact": -15}
        elif age_days < 365:
            return {"status": "warning", "description": f"Domain relatively new ({age_days} days)", "score_impact": -10}

        return {"status": "safe", "description": "Domain age looks safe", "score_impact": 0}

    except Exception:
        return {"status": "warning", "description": "Domain check failed", "score_impact": 0}

# -------------------------------
# Analyzer: Content (simulated)
# -------------------------------
def analyze_content(url):
    url_lower = url.lower()
    if any(x in url_lower for x in ['login', 'signin']):
        return {"status": "warning", "description": "Login form detected", "score_impact": -5}
    return {"status": "safe", "description": "No suspicious content", "score_impact": 0}

# -------------------------------
# Analyzer: Server (simulated)
# -------------------------------
def analyze_server(url):
    if 'free-gift-card' in url or 'secure-banking' in url:
        return {"status": "warning", "description": "Server may be risky", "score_impact": -10}
    return {"status": "safe", "description": "Server looks normal", "score_impact": 0}

# -------------------------------
# Analyzer: Phishing DB (disabled)
# -------------------------------
def check_threat_database(url):
    return {
        "status": "safe",
        "description": "Not in known phishing databases (simulation)",
        "score_impact": 0
    }

# -------------------------------
# Main API
# -------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Run analyzers
    results = {
        "url_structure": analyze_url_structure(url),
        "ssl": analyze_ssl(url),
        "domain": analyze_domain(url),
        "content": analyze_content(url),
        "server": analyze_server(url),
        "database": check_threat_database(url),
    }

    # Score calculation
    score = 100
    for r in results.values():
        score += r["score_impact"]
    score = max(0, min(100, score))

    # Verdict
    if score >= 80:
        verdict, status_class = "Likely Safe", "safe"
    elif score >= 50:
        verdict, status_class = "Suspicious", "suspicious"
    else:
        verdict, status_class = "Likely Phishing", "danger"

    return jsonify({
        "url": url,
        "score": score,
        "verdict": verdict,
        "status_class": status_class,
        "analysis": results
    })

if __name__ == "__main__":
    app.run(debug=True, port=5000)
