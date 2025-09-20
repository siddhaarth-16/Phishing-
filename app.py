from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import tldextract
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
import ssl
import socket
import hashlib
import json
import ipaddress
import urllib.request
from urllib.error import URLError, HTTPError
import math
import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
CORS(app)  # Enable CORS for frontend

# MySQL Database Configuration
MYSQL_CONFIG = {
    'host': os.getenv('MYSQL_HOST', 'localhost'),
    'database': os.getenv('MYSQL_DATABASE', 'phishing_detection'),
    'user': os.getenv('MYSQL_USER', 'root'),
    'password': os.getenv('MYSQL_PASSWORD', 'siddhu@02'),
    'port': os.getenv('MYSQL_PORT', 3306)} 


# -------------------------------
# MySQL Database Functions
# -------------------------------
def get_db_connection():
    """Create and return a MySQL database connection"""
    try:
        connection = mysql.connector.connect(**MYSQL_CONFIG)
        return connection
    except Error as e:
        print(f"Error connecting to MySQL database: {e}")
        return None

def init_database():
    """Initialize the MySQL database with required tables"""
    connection = get_db_connection()
    if connection is None:
        return False
    
    try:
        cursor = connection.cursor()
        
        # Create database if it doesn't exist
        cursor.execute(f"CREATE DATABASE IF NOT EXISTS {MYSQL_CONFIG['database']}")
        cursor.execute(f"USE {MYSQL_CONFIG['database']}")
        
        # Create table for scan results
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_results (
            id INT AUTO_INCREMENT PRIMARY KEY,
            url TEXT NOT NULL,
            url_hash VARCHAR(32) UNIQUE NOT NULL,
            score INT NOT NULL,
            verdict VARCHAR(50) NOT NULL,
            status_class VARCHAR(20) NOT NULL,
            analysis_json JSON NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX url_hash_index (url_hash),
            INDEX timestamp_index (timestamp)
        )
        ''')
        
        # Create table for caching WHOIS data
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS whois_cache (
            domain VARCHAR(255) PRIMARY KEY,
            data JSON NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX domain_index (domain)
        )
        ''')
        
        # Create table for spam detection patterns
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS spam_patterns (
            id INT AUTO_INCREMENT PRIMARY KEY,
            pattern_type VARCHAR(20) NOT NULL,
            pattern VARCHAR(255) NOT NULL,
            weight INT NOT NULL,
            UNIQUE(pattern_type, pattern),
            INDEX pattern_type_index (pattern_type)
        )
        ''')
        
        # Initialize with default spam patterns if table is empty
        cursor.execute('SELECT COUNT(*) FROM spam_patterns')
        if cursor.fetchone()[0] == 0:
            # Default spam keywords
            spam_keywords = [
                ('keyword', 'free', -15),
                ('keyword', 'win', -10),
                ('keyword', 'prize', -15),
                ('keyword', 'lottery', -20),
                ('keyword', 'reward', -10),
                ('keyword', 'claim', -15),
                ('keyword', 'selected', -10),
                ('keyword', 'winner', -15),
                ('keyword', 'congratulations', -20),
                ('keyword', 'urgent', -10),
                ('keyword', 'important', -10),
                ('keyword', 'account', -5),
                ('keyword', 'verification', -10),
                ('keyword', 'security', -5),
                ('keyword', 'update', -5),
                ('keyword', 'limited', -10),
                ('keyword', 'offer', -10),
                ('keyword', 'discount', -5),
                ('keyword', 'bonus', -10),
                ('keyword', 'guaranteed', -15),
                ('tld', '.xyz', -5),
                ('tld', '.top', -5),
                ('tld', '.club', -5),
                ('tld', '.info', -5),
                ('tld', '.tk', -10),
                ('tld', '.ml', -10),
                ('tld', '.ga', -10),
                ('tld', '.cf', -10),
                ('tld', '.gq', -10),
                ('tld', '.pw', -5),
            ]
            
            insert_query = 'INSERT INTO spam_patterns (pattern_type, pattern, weight) VALUES (%s, %s, %s)'
            cursor.executemany(insert_query, spam_keywords)
        
        connection.commit()
        cursor.close()
        connection.close()
        return True
        
    except Error as e:
        print(f"Error initializing database: {e}")
        return False

# Initialize database on startup
init_database()

# -------------------------------
# Spam Pattern Management
# -------------------------------
def load_spam_patterns():
    """Load spam patterns from database"""
    try:
        connection = get_db_connection()
        if connection is None:
            return {'keyword': [], 'tld': []}
            
        cursor = connection.cursor()
        cursor.execute('SELECT pattern_type, pattern, weight FROM spam_patterns')
        
        patterns = {'keyword': [], 'tld': []}
        
        for (pattern_type, pattern, weight) in cursor:
            if pattern_type in patterns:
                patterns[pattern_type].append((pattern, weight))
        
        cursor.close()
        connection.close()
        return patterns
    except Error as e:
        print(f"Error loading spam patterns: {e}")
        return {'keyword': [], 'tld': []}

def add_spam_pattern(pattern_type, pattern, weight):
    """Add a new spam pattern to the database"""
    try:
        connection = get_db_connection()
        if connection is None:
            return False
            
        cursor = connection.cursor()
        cursor.execute(
            'INSERT INTO spam_patterns (pattern_type, pattern, weight) VALUES (%s, %s, %s) '
            'ON DUPLICATE KEY UPDATE weight = %s',
            (pattern_type, pattern.lower(), weight, weight)
        )
        
        connection.commit()
        cursor.close()
        connection.close()
        return True
    except Error as e:
        print(f"Error adding spam pattern: {e}")
        return False

# -------------------------------
# Database Functions
# -------------------------------
def save_scan_result(url, score, verdict, status_class, analysis):
    """Save scan result to database"""
    try:
        url_hash = hashlib.md5(url.encode()).hexdigest()
        analysis_json = json.dumps(analysis)
        
        connection = get_db_connection()
        if connection is None:
            return False
            
        cursor = connection.cursor()
        
        cursor.execute('''
        INSERT INTO scan_results 
        (url, url_hash, score, verdict, status_class, analysis_json)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE 
            score = VALUES(score),
            verdict = VALUES(verdict),
            status_class = VALUES(status_class),
            analysis_json = VALUES(analysis_json),
            timestamp = CURRENT_TIMESTAMP
        ''', (url, url_hash, score, verdict, status_class, analysis_json))
        
        connection.commit()
        cursor.close()
        connection.close()
        return True
    except Error as e:
        print(f"Error saving scan result: {e}")
        return False

def get_scan_history(limit=50):
    """Retrieve scan history from database"""
    try:
        connection = get_db_connection()
        if connection is None:
            return []
            
        cursor = connection.cursor()
        cursor.execute('''
        SELECT id, url, score, verdict, status_class, timestamp 
        FROM scan_results 
        ORDER BY timestamp DESC 
        LIMIT %s
        ''', (limit,))
        
        results = []
        for (id, url, score, verdict, status_class, timestamp) in cursor:
            results.append({
                "id": id,
                "url": url,
                "score": score,
                "verdict": verdict,
                "status_class": status_class,
                "timestamp": timestamp
            })
        
        cursor.close()
        connection.close()
        return results
    except Error as e:
        print(f"Error retrieving scan history: {e}")
        return []

def get_scan_result(url):
    """Check if a URL has been scanned before"""
    try:
        url_hash = hashlib.md5(url.encode()).hexdigest()
        
        connection = get_db_connection()
        if connection is None:
            return None
            
        cursor = connection.cursor()
        cursor.execute('''
        SELECT url, score, verdict, status_class, analysis_json, timestamp 
        FROM scan_results 
        WHERE url_hash = %s
        ''', (url_hash,))
        
        row = cursor.fetchone()
        cursor.close()
        connection.close()
        
        if row:
            return {
                "url": row[0],
                "score": row[1],
                "verdict": row[2],
                "status_class": row[3],
                "analysis": json.loads(row[4]),
                "timestamp": row[5]
            }
        return None
    except Error as e:
        print(f"Error retrieving scan result: {e}")
        return None

# -------------------------------
# WHOIS Cache with Database
# -------------------------------
def cached_whois(domain):
    """Cache WHOIS lookups in database to avoid repeated requests"""
    try:
        connection = get_db_connection()
        if connection is None:
            return None
            
        cursor = connection.cursor()
        
        # Check if we have a cached result
        cursor.execute('SELECT data FROM whois_cache WHERE domain = %s', (domain,))
        row = cursor.fetchone()
        
        if row:
            cursor.close()
            connection.close()
            return json.loads(row[0])
        
        # If not cached, perform WHOIS lookup
        try:
            data = whois.whois(domain)
            # Convert datetime objects to strings for JSON serialization
            whois_data = {}
            for key, value in data.items():
                if isinstance(value, datetime):
                    whois_data[key] = value.isoformat()
                elif isinstance(value, list) and value and isinstance(value[0], datetime):
                    whois_data[key] = [v.isoformat() for v in value]
                else:
                    whois_data[key] = value
            
            # Cache the result
            cursor.execute(
                'INSERT INTO whois_cache (domain, data) VALUES (%s, %s) '
                'ON DUPLICATE KEY UPDATE data = %s, timestamp = CURRENT_TIMESTAMP',
                (domain, json.dumps(whois_data), json.dumps(whois_data))
            )
            connection.commit()
            cursor.close()
            connection.close()
            return data
        except Exception as e:
            print(f"WHOIS lookup failed for {domain}: {e}")
            cursor.close()
            connection.close()
            return None
            
    except Error as e:
        print(f"WHOIS cache error: {e}")
        return None

# -------------------------------
# Enhanced Spam Detection Functions
# -------------------------------
def detect_spam_keywords(url, patterns):
    """Detect spam keywords in URL"""
    issues = []
    score_impact = 0
    url_lower = url.lower()
    decoded_url = unquote(url_lower)  # Decode URL-encoded characters
    
    for keyword, weight in patterns.get('keyword', []):
        # Check both encoded and decoded versions
        if keyword in url_lower or keyword in decoded_url:
            issues.append(f"Spam keyword detected: '{keyword}'")
            score_impact += weight
    
    return issues, score_impact

def detect_suspicious_tld(domain, patterns):
    """Check for suspicious TLDs"""
    issues = []
    score_impact = 0
    
    ext = tldextract.extract(domain)
    tld = f".{ext.suffix}"
    
    for pattern_tld, weight in patterns.get('tld', []):
        if tld == pattern_tld:
            issues.append(f"Suspicious TLD detected: {tld}")
            score_impact += weight
            break
    
    return issues, score_impact

def analyze_url_entropy(url):
    """Analyze URL entropy for obfuscation detection"""
    # Calculate Shannon entropy of the URL
    url_lower = url.lower()
    entropy = 0
    
    if len(url_lower) > 0:
        # Count frequency of each character
        freq = {}
        for char in url_lower:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        for count in freq.values():
            probability = count / len(url_lower)
            entropy -= probability * (probability and math.log(probability, 2))
    
    issues = []
    score_impact = 0
    
    # High entropy may indicate random-looking URLs often used in spam
    if entropy > 4.5:  # Empirical threshold
        issues.append(f"High entropy detected ({entropy:.2f}), possible obfuscation")
        score_impact -= 10
    
    return issues, score_impact

def check_url_shorteners(url):
    """Check if URL uses known URL shorteners"""
    shorteners = [
        'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly', 'buff.ly', 
        'adf.ly', 'shorte.st', 'bc.vc', 'tiny.cc', 'bit.do', 'clk.sh', 
        'ity.im', 'soo.gd', 'is.gd', 'v.gd', 'clicky.me', 'cutt.ly', 
        'shrink.me', 'qr.net', 'vurl.com', 'x.co', 'zzb.bz'
    ]
    
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    
    issues = []
    score_impact = 0
    
    for shortener in shorteners:
        if shortener in domain:
            issues.append(f"URL shortener detected: {shortener}")
            score_impact -= 15
            break
    
    return issues, score_impact

def check_redirects(url):
    """Check for excessive redirects"""
    try:
        # Don't follow redirects, just check headers
        req = urllib.request.Request(
            url, 
            headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        )
        
        with urllib.request.urlopen(req, timeout=5) as response:
            # Check if there's a redirect
            if response.geturl() != url:
                return ["URL redirects to another location"], -10
                
    except (URLError, HTTPError, socket.timeout):
        pass  # We'll handle this in the SSL check
    
    return [], 0

# -------------------------------
# Enhanced Analyzer Functions
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
    try:
        ipaddress.ip_address(host)
        issues.append("Uses raw IP address instead of domain")
        score_impact -= 20
    except ValueError:
        pass  # Not an IP address

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

    # Load spam patterns and check
    spam_patterns = load_spam_patterns()
    
    # Check for spam keywords
    spam_issues, spam_impact = detect_spam_keywords(url, spam_patterns)
    issues.extend(spam_issues)
    score_impact += spam_impact
    
    # Check for suspicious TLDs
    tld_issues, tld_impact = detect_suspicious_tld(host, spam_patterns)
    issues.extend(tld_issues)
    score_impact += tld_impact
    
    # Check for URL shorteners
    shortener_issues, shortener_impact = check_url_shorteners(url)
    issues.extend(shortener_issues)
    score_impact += shortener_impact
    
    # Check for redirects
    redirect_issues, redirect_impact = check_redirects(url)
    issues.extend(redirect_issues)
    score_impact += redirect_impact

    return {
        "status": "danger" if issues else "warning" if warnings else "safe",
        "description": issues[0] if issues else warnings[0] if warnings else "Normal structure",
        "score_impact": score_impact,
        "details": issues + warnings
    }

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

def analyze_content(url):
    url_lower = url.lower()
    if any(x in url_lower for x in ['login', 'signin']):
        return {"status": "warning", "description": "Login form detected", "score_impact": -5}
    return {"status": "safe", "description": "No suspicious content", "score_impact": 0}

def analyze_server(url):
    if 'free-gift-card' in url or 'secure-banking' in url:
        return {"status": "warning", "description": "Server may be risky", "score_impact": -10}
    return {"status": "safe", "description": "Server looks normal", "score_impact": 0}

def check_threat_database(url):
    return {
        "status": "safe",
        "description": "Not in known phishing databases (simulation)",
        "score_impact": 0
    }

# -------------------------------
# API Routes
# -------------------------------
@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "URL required"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # Check if we already have results for this URL
    existing_result = get_scan_result(url)
    if existing_result:
        return jsonify({
            "url": existing_result["url"],
            "score": existing_result["score"],
            "verdict": existing_result["verdict"],
            "status_class": existing_result["status_class"],
            "analysis": existing_result["analysis"],
            "from_cache": True,
            "timestamp": existing_result["timestamp"]
        })

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

    # Save results
    save_scan_result(url, score, verdict, status_class, results)

    return jsonify({
        "url": url,
        "score": score,
        "verdict": verdict,
        "status_class": status_class,
        "analysis": results,
        "from_cache": False,
        "timestamp": datetime.now().isoformat()
    })

@app.route("/history", methods=["GET"])
def get_history():
    """Get scan history"""
    limit = request.args.get("limit", 50, type=int)
    history = get_scan_history(limit)
    return jsonify({"history": history})

@app.route("/result/<int:result_id>", methods=["GET"])
def get_result_by_id(result_id):
    """Get detailed result by ID"""
    try:
        connection = get_db_connection()
        if connection is None:
            return jsonify({"error": "Database connection failed"}), 500
            
        cursor = connection.cursor()
        cursor.execute('''
        SELECT url, score, verdict, status_class, analysis_json, timestamp 
        FROM scan_results 
        WHERE id = %s
        ''', (result_id,))
        
        row = cursor.fetchone()
        cursor.close()
        connection.close()
        
        if row:
            return jsonify({
                "url": row[0],
                "score": row[1],
                "verdict": row[2],
                "status_class": row[3],
                "analysis": json.loads(row[4]),
                "timestamp": row[5]
            })
        return jsonify({"error": "Result not found"}), 404
    except Error as e:
        return jsonify({"error": str(e)}), 500

@app.route("/spam-patterns", methods=["GET"])
def get_spam_patterns():
    """Get all spam patterns"""
    try:
        patterns = load_spam_patterns()
        return jsonify({"patterns": patterns})
    except Error as e:
        return jsonify({"error": str(e)}), 500

@app.route("/spam-patterns", methods=["POST"])
def add_spam_pattern_api():
    """Add a new spam pattern"""
    try:
        data = request.get_json()
        pattern_type = data.get("pattern_type")
        pattern = data.get("pattern")
        weight = data.get("weight")
        
        if not all([pattern_type, pattern, weight]):
            return jsonify({"error": "Missing required fields"}), 400
        
        if add_spam_pattern(pattern_type, pattern, weight):
            return jsonify({"message": "Pattern added successfully"})
        else:
            return jsonify({"error": "Failed to add pattern"}), 500
            
    except Error as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint"""
    try:
        connection = get_db_connection()
        if connection:
            connection.close()
            return jsonify({
                "status": "healthy", 
                "database": "connected",
                "timestamp": datetime.now().isoformat()
            })
        else:
            return jsonify({
                "status": "degraded", 
                "database": "disconnected",
                "timestamp": datetime.now().isoformat()
            }), 500
    except Error:
        return jsonify({
            "status": "degraded", 
            "database": "disconnected",
            "timestamp": datetime.now().isoformat()
        }), 500

if __name__ == "__main__":
    app.run(debug=True, port=5000)
