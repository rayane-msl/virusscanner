"""
Website Scanner Module
Handles scanning of websites for malicious content and phishing attempts
"""

import os
import asyncio
import re
import json
from datetime import datetime
from typing import Dict, Any, Optional, List
from urllib.parse import urlparse, urljoin
import aiohttp
import requests
from bs4 import BeautifulSoup
from fake_useragent import UserAgent

from config import (
    SCAN_TIMEOUT, 
    MAX_URL_LENGTH, 
    ALLOWED_PROTOCOLS,
    SUSPICIOUS_PATTERNS,
    VIRUSTOTAL_API_KEY,
    GOOGLE_SAFE_BROWSING_API_KEY
)

class WebsiteScanner:
    """Scanner for websites with multiple detection engines"""
    
    def __init__(self):
        self.scanner_name = "Telescan Website Scanner"
        self.version = "1.0.0"
        self.user_agent = UserAgent()
        self.session = requests.Session()
        self.active = True
        print(f"[INFO] Website scanner initialized")
    
    def get_status(self) -> Dict[str, Any]:
        """Get scanner status"""
        return {
            "name": self.scanner_name,
            "version": self.version,
            "engine": "HTTP Analysis + Content Scanning + External APIs",
            "active": self.active,
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}",
            "website_apis": ["VirusTotal", "Google Safe Browsing"] if VIRUSTOTAL_API_KEY else []
        }
    
    async def scan_website(self, url: str) -> Dict[str, Any]:
        """
        Scan a website for malicious content
        
        Args:
            url: URL of the website to scan
            
        Returns:
            Dictionary with scan results
        """
        result = {
            "url": url,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "threats": [],
            "warnings": [],
            "clean": True,
            "details": {}
        }
        
        # Validate URL
        if not self._validate_url(url):
            result["error"] = "Invalid URL format"
            result["clean"] = False
            return result
        
        try:
            # Get website information
            site_info = await self._get_website_info(url)
            result["details"]["site_info"] = site_info
            
            # Check URL against known malicious databases
            url_check = await self._check_url_databases(url)
            if url_check["malicious"]:
                result["threats"].extend(url_check["threats"])
                result["clean"] = False
            
            # Analyze website content
            content_analysis = await self._analyze_content(url)
            if content_analysis["suspicious"]:
                result["warnings"].extend(content_analysis["details"])
            
            # Check for phishing indicators
            phishing_check = await self._check_phishing_indicators(url, content_analysis)
            if phishing_check["detected"]:
                result["threats"].extend(phishing_check["threats"])
                result["clean"] = False
            
            # Check SSL/TLS security
            ssl_check = await self._check_ssl_security(url)
            if ssl_check["issues"]:
                result["warnings"].extend(ssl_check["issues"])
            
            # Perform external API checks
            if VIRUSTOTAL_API_KEY:
                vt_check = await self._check_virustotal(url)
                if vt_check.get("malicious"):
                    result["threats"].extend(vt_check["threats"])
                    result["clean"] = False
            
            if GOOGLE_SAFE_BROWSING_API_KEY:
                gsb_check = await self._check_google_safe_browsing(url)
                if gsb_check.get("unsafe"):
                    result["threats"].extend(gsb_check["threats"])
                    result["clean"] = False
            
            # Generate overall score
            result["details"]["threat_count"] = len(result["threats"])
            result["details"]["warning_count"] = len(result["warnings"])
            result["details"]["is_safe"] = result["clean"]
            
        except Exception as e:
            result["error"] = str(e)
            result["clean"] = False
        
        return result
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        if len(url) > MAX_URL_LENGTH:
            return False
        
        # Check protocol
        if not any(url.startswith(protocol) for protocol in ALLOWED_PROTOCOLS):
            return False
        
        # Basic URL validation
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    async def _get_website_info(self, url: str) -> Dict[str, Any]:
        """Get basic website information"""
        info = {
            "domain": None,
            "ip_address": None,
            "title": None,
            "server": None,
            "content_type": None,
            "response_time": 0
        }
        
        try:
            start_time = asyncio.get_event_loop().time()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT)) as response:
                    end_time = asyncio.get_event_loop().time()
                    info["response_time"] = round(end_time - start_time, 3)
                    info["status_code"] = response.status
                    info["content_type"] = response.headers.get("content-type", "")
                    info["server"] = response.headers.get("server", "")
                    
                    # Parse URL for domain
                    parsed = urlparse(url)
                    info["domain"] = parsed.netloc
                    
                    # Get page title
                    if "text/html" in info["content_type"]:
                        html = await response.text()
                        soup = BeautifulSoup(html, 'lxml')
                        title = soup.find('title')
                        info["title"] = title.string if title else None
            
            # Get IP address
            try:
                import socket
                hostname = info["domain"].split(':')[0]  # Remove port if present
                ip_address = socket.gethostbyname(hostname)
                info["ip_address"] = ip_address
            except Exception:
                info["ip_address"] = "Unknown"
                
        except Exception as e:
            info["error"] = str(e)
        
        return info
    
    async def _check_url_databases(self, url: str) -> Dict[str, Any]:
        """Check URL against known malicious URL databases"""
        result = {"malicious": False, "threats": []}
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Check against suspicious TLDs
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.loan', '.download', '.stream']
        for tld in suspicious_tlds:
            if domain.lower().endswith(tld):
                result["threats"].append({
                    "type": "Suspicious TLD",
                    "description": f"Domain uses suspicious TLD ({tld})",
                    "source": "Local Database",
                    "severity": "medium"
                })
                result["malicious"] = True
        
        # Check for IP addresses instead of domains
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain.split(':')[0]):
            result["threats"].append({
                "type": "IP Address URL",
                "description": "URL uses IP address instead of domain name",
                "source": "Local Database",
                "severity": "medium"
            })
        
        return result
    
    async def _analyze_content(self, url: str) -> Dict[str, Any]:
        """Analyze website content for suspicious patterns"""
        result = {"suspicious": False, "details": []}
        
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'User-Agent': self.user_agent.random}
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=SCAN_TIMEOUT)) as response:
                    if response.status != 200:
                        result["details"].append({
                            "type": "HTTP Status",
                            "description": f"Unusual HTTP status code: {response.status}",
                            "source": "Content Analysis"
                        })
                        result["suspicious"] = True
                        return result
                    
                    content = await response.text()
                    content_lower = content.lower()
                    
                    # Check for suspicious patterns in content
                    for pattern, description in SUSPICIOUS_PATTERNS:
                        if re.search(pattern, content_lower):
                            result["details"].append({
                                "type": "Content Pattern",
                                "description": description,
                                "source": "Content Analysis"
                            })
                            result["suspicious"] = True
                    
                    # Check for excessive external links
                    soup = BeautifulSoup(content, 'lxml')
                    external_links = soup.find_all('a', href=True)
                    external_count = len([link for link in external_links 
                                         if link['href'].startswith('http') 
                                         and urlparse(link['href']).netloc != urlparse(url).netloc])
                    
                    if external_count > 50:
                        result["details"].append({
                            "type": "External Links",
                            "description": f"Excessive external links detected ({external_count})",
                            "source": "Content Analysis"
                        })
                    
                    # Check for login forms (potential phishing)
                    login_forms = soup.find_all('form', {'type': 'password'})
                    if login_forms and 'login' not in url.lower() and 'signin' not in url.lower():
                        result["details"].append({
                            "type": "Login Form",
                            "description": "Login form detected on non-login page",
                            "source": "Content Analysis"
                        })
                    
                    # Check for iframe usage
                    iframes = soup.find_all('iframe')
                    if iframes:
                        result["details"].append({
                            "type": "Iframes",
                            "description": f"Iframe elements detected ({len(iframes)})",
                            "source": "Content Analysis"
                        })
                    
        except Exception as e:
            result["details"].append({"error": str(e)})
        
        return result
    
    async def _check_phishing_indicators(self, url: str, content_analysis: Dict) -> Dict[str, Any]:
        """Check for phishing indicators"""
        result = {"detected": False, "threats": []}
        
        parsed = urlparse(url)
        domain = parsed.netloc
        
        # Check for URL shortening services
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'buff.ly']
        if any(shortener in domain.lower() for shortener in shorteners):
            result["threats"].append({
                "type": "URL Shortener",
                "description": "URL shortening service detected - hides true destination",
                "source": "Phishing Detection",
                "severity": "medium"
            })
            result["detected"] = True
        
        # Check for homograph attacks (lookalike domains)
        if len(domain) > 20:
            result["threats"].append({
                "type": "Long Domain",
                "description": "Unusually long domain name - potential phishing",
                "source": "Phishing Detection",
                "severity": "low"
            })
        
        # Check for multiple subdomains
        if domain.count('.') > 2:
            result["threats"].append({
                "type": "Multiple Subdomains",
                "description": "Excessive subdomain usage - potential phishing",
                "source": "Phishing Detection",
                "severity": "low"
            })
        
        # Check for suspicious keywords in domain
        suspicious_domain_words = ['login', 'signin', 'account', 'verify', 'secure', 'update', 'banking']
        if any(word in domain.lower() for word in suspicious_domain_words):
            result["threats"].append({
                "type": "Suspicious Keywords",
                "description": "Domain contains security-sensitive keywords",
                "source": "Phishing Detection",
                "severity": "medium"
            })
        
        return result
    
    async def _check_ssl_security(self, url: str) -> Dict[str, Any]:
        """Check SSL/TLS security configuration"""
        result = {"issues": []}
        
        if not url.startswith('https://'):
            result["issues"].append({
                "type": "No SSL",
                "description": "Website does not use HTTPS encryption",
                "severity": "high"
            })
            return result
        
        try:
            import ssl
            hostname = urlparse(url).netloc
            
            # Create SSL context
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.now():
                        result["issues"].append({
                            "type": "Expired Certificate",
                            "description": "SSL certificate has expired",
                            "severity": "critical"
                        })
                    
                    # Check certificate issuer
                    issuer = dict(x[0] for x in cert['issuer'])
                    if 'organizationName' not in issuer:
                        result["issues"].append({
                            "type": "Untrusted Issuer",
                            "description": "Certificate issued by untrusted organization",
                            "severity": "medium"
                        })
                        
        except Exception as e:
            result["issues"].append({
                "type": "SSL Check Failed",
                "description": f"Could not verify SSL certificate: {str(e)}",
                "severity": "low"
            })
        
        return result
    
    async def _check_virustotal(self, url: str) -> Dict[str, Any]:
        """Check URL using VirusTotal API"""
        result = {"malicious": False, "threats": []}
        
        if not VIRUSTOTAL_API_KEY:
            return result
        
        try:
            headers = {'x-apikey': VIRUSTOTAL_API_KEY}
            
            # Submit URL for analysis
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    'https://www.virustotal.com/api/v3/urls',
                    headers=headers,
                    data={'url': url}
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        analysis_id = data['data']['id']
                        
                        # Wait a bit for analysis
                        await asyncio.sleep(2)
                        
                        # Get analysis results
                        async with session.get(
                            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
                            headers=headers
                        ) as analysis_response:
                            if analysis_response.status == 200:
                                analysis_data = await analysis_response.json()
                                stats = analysis_data['data']['attributes']['stats']
                                if stats['malicious'] > 0:
                                    result["malicious"] = True
                                    result["threats"].append({
                                        "type": "VirusTotal Detection",
                                        "description": f"Detected by {stats['malicious']} security vendors",
                                        "source": "VirusTotal",
                                        "severity": "critical"
                                    })
                                    
        except Exception as e:
            print(f"[WARNING] VirusTotal API error: {e}")
        
        return result
    
    async def _check_google_safe_browsing(self, url: str) -> Dict[str, Any]:
        """Check URL using Google Safe Browsing API"""
        result = {"unsafe": False, "threats": []}
        
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            return result
        
        try:
            api_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
            
            payload = {
                "client": {
                    "clientId": "telescan-bot",
                    "clientVersion": "1.0.0"
                },
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            
            response = requests.post(api_url, json=payload)
            
            if response.status_code == 200 and response.json().get('matches'):
                result["unsafe"] = True
                for match in response.json()['matches']:
                    result["threats"].append({
                        "type": match['threatType'].replace('_', ' ').title(),
                        "description": match['threatDescription'],
                        "source": "Google Safe Browsing",
                        "severity": "high"
                    })
                    
        except Exception as e:
            print(f"[WARNING] Google Safe Browsing API error: {e}")
        
        return result
