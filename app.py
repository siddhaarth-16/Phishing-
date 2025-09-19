from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import tldextract
import whois
from datetime import datetime
import requests
from urllib.parse import urlparse
import ssl
import socket
import random

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

def analyze_url_structure(url):
    """Analyze URL structure for phishing indicators"""
    issues = []
    warnings = []
    score_impact = 0
    
    # Check for HTTPS
    if not url.startswith('https://'):
        issues.append('Website does not use HTTPS (secure connection)')
        score_impact -= 20
    
    # Check for IP address instead of domain
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_regex, url)
    if ip_match:
        issues.append(f'Uses IP address ({ip_match.group(0)}) instead of domain name')
        score_impact -= 15
    
    # Check for suspicious characters (@ in main URL)
    if '@' in url and url.find('@') > url.find('//') + 2:
        issues.append('Contains suspicious "@" character often used for embedding credentials')
        score_impact -= 15
    
    # Check for multiple subdomains
    try:
        parsed_url = urlparse(url)
        hostname_parts = parsed_url.hostname.split('.')
        if len(hostname_parts) > 3:
            warnings.append('Multiple subdomains detected (common in phishing URLs)')
            score_impact -= 10
    except:
        pass
    
    # Check for URL encoding attempts
    if '%' in url and any(x in url for x in ['%2F', '%3F', '%3D', '%26']):
        issues.append('Contains encoded characters that may be attempting to obfuscate malicious content')
        score_impact -= 10
    
    # Check for brand names in subdomains
    brands = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'bank', 'facebook', 'ebay']
    found_brands = [brand for brand in brands if brand in url.lower()]
    
    if found_brands:
        try:
            parsed_url = urlparse(url)
            if not (parsed_url.hostname.endswith('.com') or 
                    parsed_url.hostname.endswith('.org') or 
                    parsed_url.hostname.endswith('.net')):
                issues.append(f'Uses brand name ({found_brands[0]}) in a suspicious context')
                score_impact -= 20
        except:
            pass
    
    # Check for long URLs
    if len(url) > 75:
        warnings.append('URL is unusually long (common tactic in phishing attempts)')
        score_impact -= 5
    
    # Check for port numbers
    port_match = re.search(r':(\d+)', url)
    if port_match and port_match.group(1) not in ['80', '443']:
        warnings.append(f'Uses non-standard port ({port_match.group(0)}) which is unusual for web traffic')
        score_impact -= 5
    
    # Prepare detailed results
    analysis_details = []
    
    if issues or warnings:
        for issue in issues:
            analysis_details.append({
                'type': 'warning',
                'icon': 'exclamation-circle',
                'message': issue
            })
        
        for warning in warnings:
            analysis_details.append({
                'type': 'warning',
                'icon': 'exclamation-triangle',
                'message': warning
            })
    else:
        analysis_details.append({
            'type': 'safe',
            'icon': 'check-circle',
            'message': 'No suspicious URL patterns detected'
        })
    
    # Determine status
    if issues:
        status = 'danger'
        description = issues[0]
    elif warnings:
        status = 'warning'
        description = warnings[0]
    else:
        status = 'safe'
        description = 'URL structure appears normal'
    
    return {
        'status': status,
        'description': description,
        'score_impact': score_impact,
        'details': analysis_details
    }

def analyze_ssl(url):
    """Check SSL certificate validity"""
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        
        if not hostname:
            return {
                'status': 'danger',
                'description': 'Invalid URL',
                'score_impact': -20
            }
        
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                
        # Check if certificate is valid
        cert_expires = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        if datetime.now() > cert_expires:
            return {
                'status': 'danger',
                'description': 'SSL certificate has expired',
                'score_impact': -20
            }
        
        return {
            'status': 'safe',
            'description': 'SSL certificate is valid',
            'score_impact': 10
        }
    
    except Exception as e:
        return {
            'status': 'danger',
            'description': f'SSL certificate error: {str(e)}',
            'score_impact': -20
        }

def analyze_domain(url):
    """Analyze domain age and reputation"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.hostname
        
        if not domain:
            return {
                'status': 'danger',
                'description': 'Invalid domain',
                'score_impact': -20
            }
        
        # Extract domain info using whois
        domain_info = whois.whois(domain)
        
        # Check creation date
        if domain_info.creation_date:
            if isinstance(domain_info.creation_date, list):
                creation_date = domain_info.creation_date[0]
            else:
                creation_date = domain_info.creation_date
            
            domain_age = (datetime.now() - creation_date).days
            
            if domain_age < 30:
                return {
                    'status': 'danger',
                    'description': f'Domain was registered recently ({domain_age} days ago)',
                    'score_impact': -15
                }
            elif domain_age < 365:
                return {
                    'status': 'warning',
                    'description': f'Domain is relatively new ({domain_age} days old)',
                    'score_impact': -10
                }
        
        # Check for suspicious keywords in domain
        suspicious_keywords = ['free', 'gift', 'verify', 'security', 'alert', 'account', 'login']
        domain_lower = domain.lower()
        
        for keyword in suspicious_keywords:
            if keyword in domain_lower:
                return {
                    'status': 'warning',
                    'description': f'Domain contains suspicious keyword: "{keyword}"',
                    'score_impact': -15
                }
        
        return {
            'status': 'safe',
            'description': 'Domain is reputable',
            'score_impact': 5
        }
    
    except Exception as e:
        return {
            'status': 'warning',
            'description': 'Could not retrieve domain information',
            'score_impact': -5
        }

def analyze_content(url):
    """Analyze page content (simulated)"""
    # In a real implementation, this would fetch the page and analyze its content
    # For this example, we'll simulate based on URL patterns
    
    # Check for brand names in suspicious contexts
    brands = ['paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix', 'bank', 'facebook', 'ebay']
    url_lower = url.lower()
    
    for brand in brands:
        if brand in url_lower:
            # Check if it's likely the real domain
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}"
            
            if brand not in domain:
                return {
                    'status': 'warning',
                    'description': f'Content mimics known brand ({brand})',
                    'score_impact': -15
                }
    
    # Simulate other content checks
    if 'login' in url_lower or 'signin' in url_lower:
        return {
            'status': 'warning',
            'description': 'Login page detected - be cautious with credentials',
            'score_impact': -5
        }
    
    return {
        'status': 'safe',
        'description': 'Content appears legitimate',
        'score_impact': 5
    }

def analyze_server(url):
    """Analyze server information (simulated)"""
    # In a real implementation, this would check server headers, IP reputation, etc.
    
    # Simulate based on URL patterns
    if 'free-gift-card' in url or 'secure-banking' in url:
        return {
            'status': 'warning',
            'description': 'Server is hosted in a high-risk location',
            'score_impact': -10
        }
    
    return {
        'status': 'safe',
        'description': 'Server location and provider are reputable',
        'score_impact': 5
    }

def check_threat_database(url):
    """Check URL against threat databases (simulated)"""
    # In a real implementation, this would query actual threat intelligence feeds
    
    # Simulate check with a small chance of being in a database
    if random.random() < 0.1:  # 10% chance
        return {
            'status': 'danger',
            'description': 'URL found in phishing database',
            'score_impact': -30
        }
    
    return {
        'status': 'safe',
        'description': 'Not in known phishing databases',
        'score_impact': 10
    }

@app.route('/analyze', methods=['POST'])
def analyze():
    """Main analysis endpoint"""
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    # Add http:// if no scheme is present
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Perform all analyses
    url_structure = analyze_url_structure(url)
    ssl_analysis = analyze_ssl(url)
    domain_analysis = analyze_domain(url)
    content_analysis = analyze_content(url)
    server_analysis = analyze_server(url)
    threat_analysis = check_threat_database(url)
    
    # Calculate overall score (starts at 50, then adds/subtracts based on analyses)
    score = 50
    score += url_structure['score_impact']
    score += ssl_analysis['score_impact']
    score += domain_analysis['score_impact']
    score += content_analysis['score_impact']
    score += server_analysis['score_impact']
    score += threat_analysis['score_impact']
    
    # Ensure score is between 0-100
    score = max(0, min(100, score))
    
    # Determine overall verdict
    if score >= 80:
        verdict = 'Likely Safe'
        status_class = 'safe'
    elif score >= 50:
        verdict = 'Suspicious'
        status_class = 'suspicious'
    else:
        verdict = 'Likely Phishing'
        status_class = 'danger'
    
    # Generate recommendations based on score
    recommendations = generate_recommendations(score, url)
    
    # Prepare response
    response = {
        'url': url,
        'score': score,
        'verdict': verdict,
        'status_class': status_class,
        'url_analysis': url_structure['details'],
        'analysis': {
            'url_structure': {
                'status': url_structure['status'],
                'description': url_structure['description']
            },
            'ssl': {
                'status': ssl_analysis['status'],
                'description': ssl_analysis['description']
            },
            'domain': {
                'status': domain_analysis['status'],
                'description': domain_analysis['description']
            },
            'content': {
                'status': content_analysis['status'],
                'description': content_analysis['description']
            },
            'server': {
                'status': server_analysis['status'],
                'description': server_analysis['description']
            },
            'database': {
                'status': threat_analysis['status'],
                'description': threat_analysis['description']
            }
        },
        'recommendations': recommendations
    }
    
    return jsonify(response)

def generate_recommendations(score, url):
    """Generate safety recommendations based on the analysis score"""
    if score >= 80:
        return [
            "This website appears to be safe based on our analysis.",
            "Always ensure you're visiting the correct domain for the service you're using.",
            "Keep your browser and security software up to date.",
            "Enable two-factor authentication where available for additional security."
        ]
    elif score >= 50:
        return [
            "This website has some suspicious characteristics. Proceed with caution.",
            "Check for HTTPS in the address bar before entering any information.",
            "Look for misspellings or wrong domains in the URL.",
            "Never enter passwords or sensitive data unless you're certain of the website's authenticity.",
            "Consider using a password manager to avoid entering credentials on suspicious sites."
        ]
    else:
        return [
            "This website has strong indicators of being a phishing site. Avoid interaction.",
            "Do not enter any personal information on this website.",
            "Do not download any files from this website.",
            "If you arrived here from an email, mark the email as spam.",
            "Consider reporting this website to your browser's security team.",
            "Run a security scan on your device if you've already interacted with this site."
        ]

if __name__ == '__main__':
    app.run(debug=True, port=5000)
