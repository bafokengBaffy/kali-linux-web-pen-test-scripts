#!/usr/bin/env python3
"""
ULTIMATE SECURITY HEADERS TESTER (50+ Checks)
Target: http://172.19.64.1:5000

Purpose: This script tests for missing or misconfigured security headers.
Security headers protect against various attacks like XSS, clickjacking,
MIME sniffing, and information disclosure.

Author: Security Testing Suite
Version: 2.0
Windows Target: 172.19.64.1:5000

Usage: python security_headers.py
Note: Make sure your server is running on http://172.19.64.1:5000 first
"""

import requests
import ssl
import socket
import json
import time
import hashlib
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

# Configuration
TARGET = "https://career-connect-backend-gp8u.onrender.com"
TARGET_IP = "172.19.64.1"
TARGET_PORT = 5000

class SecurityHeadersTester:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.results = {}
        self.vulnerabilities = []
        self.start_time = time.time()
    
    def print_banner(self):
        """Display comprehensive banner"""
        print("\n" + "=" * 100)
        print("🔒 ULTIMATE SECURITY HEADERS TESTER v2.0")
        print("=" * 100)
        print(f"🎯 TARGET: {self.target_url}")
        print(f"🔐 Protocol: {self.parsed_url.scheme.upper()}")
        print(f"🏠 Host: {self.parsed_url.hostname}")
        print(f"📅 Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 100)
        print("📋 Performing 50+ security header checks...")
        print("=" * 100 + "\n")
    
    def connect(self):
        """Establish connection to target"""
        print("🔌 Connecting to target...")
        
        try:
            self.response = requests.get(
                self.target_url,
                timeout=10,
                verify=False,
                allow_redirects=True
            )
            
            self.final_url = self.response.url
            self.headers = self.response.headers
            
            print(f"✅ Connected to: {self.final_url}")
            print(f"📊 Status Code: {self.response.status_code}")
            
            # Show redirect history
            if self.response.history:
                print(f"🔄 Redirects: {len(self.response.history)}")
                for i, resp in enumerate(self.response.history):
                    print(f"   {i+1}. {resp.status_code} → {resp.url}")
            
            return True
            
        except Exception as e:
            print(f"❌ Connection failed: {e}")
            return False
    
    def analyze_basic_headers(self):
        """Analyze basic security headers"""
        print("\n1️⃣  [BASIC HEADERS] Core security headers analysis")
        
        critical_headers = [
            # Header, Description, Required Value, Severity
            ('Content-Security-Policy', 'Prevents XSS and data injection', None, 'CRITICAL'),
            ('X-Frame-Options', 'Prevents clickjacking', None, 'CRITICAL'),
            ('X-Content-Type-Options', 'Prevents MIME sniffing', 'nosniff', 'CRITICAL'),
            ('Strict-Transport-Security', 'Enforces HTTPS', None, 'HIGH'),
            ('Referrer-Policy', 'Controls referrer information', None, 'MEDIUM'),
            ('Permissions-Policy', 'Controls browser features', None, 'MEDIUM'),
            ('X-XSS-Protection', 'Legacy XSS protection (deprecated)', None, 'LOW'),
        ]
        
        found_count = 0
        missing_count = 0
        
        for header, description, required, severity in critical_headers:
            if header in self.headers:
                found_count += 1
                value = self.headers[header]
                
                # Validate specific headers
                validation_result = self.validate_header(header, value)
                
                print(f"   ✅ {header}: {value[:60]}...")
                
                if validation_result:
                    print(f"      ⚠️  {validation_result}")
                    self.vulnerabilities.append(f"{header}: {validation_result}")
                
            else:
                missing_count += 1
                print(f"   ❌ {header}: MISSING ({severity} severity)")
                
                if severity in ['CRITICAL', 'HIGH']:
                    self.vulnerabilities.append(f"Missing {header} ({severity})")
        
        print(f"\n   📊 Summary: {found_count}/{len(critical_headers)} critical headers present")
        
        self.results['basic_headers'] = {
            'found': found_count,
            'missing': missing_count,
            'total': len(critical_headers)
        }
    
    def validate_header(self, header, value):
        """Validate specific header values"""
        value_lower = value.lower()
        
        if header == 'X-Frame-Options':
            if value_lower not in ['deny', 'sameorigin']:
                return f"Weak value: {value} (should be DENY or SAMEORIGIN)"
        
        elif header == 'X-Content-Type-Options':
            if value_lower != 'nosniff':
                return f"Incorrect value: {value} (should be nosniff)"
        
        elif header == 'Strict-Transport-Security':
            if 'max-age=' not in value_lower:
                return "Missing max-age directive"
            if 'includesubdomains' not in value_lower:
                return "Missing includeSubDomains directive"
            if 'preload' not in value_lower:
                return "Consider adding preload directive"
        
        elif header == 'Content-Security-Policy':
            warnings = []
            
            # Check for unsafe directives
            unsafe_patterns = [
                ("'unsafe-inline'", "Allows inline scripts/styles"),
                ("'unsafe-eval'", "Allows eval() function"),
                ("*", "Wildcard source (too permissive)"),
                ("data:", "Allows data: URIs"),
                ("blob:", "Allows blob: URIs"),
                ("'unsafe-hashes'", "Allows unsafe hashes")
            ]
            
            for pattern, description in unsafe_patterns:
                if pattern in value:
                    warnings.append(f"{description}")
            
            # Check for missing important directives
            important_directives = ['script-src', 'object-src', 'base-uri', 'frame-ancestors']
            for directive in important_directives:
                if directive not in value_lower:
                    warnings.append(f"Missing {directive} directive")
            
            if warnings:
                return f"CSP issues: {', '.join(warnings[:3])}"
        
        return None
    
    def analyze_csp_detailed(self):
        """Detailed Content Security Policy analysis"""
        print("\n2️⃣  [CSP DETAILED] Content Security Policy deep analysis")
        
        if 'Content-Security-Policy' in self.headers:
            csp = self.headers['Content-Security-Policy']
            
            # Parse CSP directives
            directives = {}
            for directive in csp.split(';'):
                directive = directive.strip()
                if ' ' in directive:
                    name, value = directive.split(' ', 1)
                    directives[name.strip()] = value.strip()
            
            print("   📋 CSP Directives found:")
            
            # Analyze each directive
            for name, value in directives.items():
                print(f"      • {name}: {value[:50]}...")
                
                # Score directive security
                score = self.score_csp_directive(name, value)
                if score < 0.5:
                    self.vulnerabilities.append(f"CSP weak directive: {name} = {value[:30]}")
            
            # Generate CSP report
            self.results['csp_analysis'] = {
                'directives_found': len(directives),
                'has_unsafe_inline': "'unsafe-inline'" in csp,
                'has_unsafe_eval': "'unsafe-eval'" in csp,
                'has_wildcard': "*" in csp,
                'recommended_score': self.calculate_csp_score(directives)
            }
            
        else:
            print("   ❌ No Content-Security-Policy header")
            self.vulnerabilities.append("Missing Content-Security-Policy (CRITICAL)")
    
    def score_csp_directive(self, name, value):
        """Score CSP directive security (0-1, higher is better)"""
        score = 1.0
        
        if name.lower() == 'script-src':
            if "'unsafe-inline'" in value:
                score -= 0.5
            if "'unsafe-eval'" in value:
                score -= 0.3
            if "*" in value and "'self'" not in value:
                score -= 0.7
            if "'self'" in value:
                score += 0.2
            if "https:" in value:
                score += 0.1
        
        elif name.lower() == 'object-src':
            if value == "'none'":
                score += 0.5
            elif "*" in value:
                score -= 0.8
        
        elif name.lower() == 'frame-ancestors':
            if value == "'none'":
                score += 0.5
            elif value == "'self'":
                score += 0.3
            elif "*" in value:
                score -= 0.9
        
        return max(0, min(1, score))
    
    def calculate_csp_score(self, directives):
        """Calculate overall CSP security score"""
        if not directives:
            return 0
        
        total_score = 0
        for name, value in directives.items():
            total_score += self.score_csp_directive(name, value)
        
        return total_score / len(directives)
    
    def analyze_cookie_security(self):
        """Analyze cookie security attributes"""
        print("\n3️⃣  [COOKIE SECURITY] Analyzing Set-Cookie headers")
        
        if 'Set-Cookie' in self.headers:
            cookies = self.headers.get_all('Set-Cookie') if hasattr(self.headers, 'get_all') else [self.headers['Set-Cookie']]
            
            cookie_analysis = []
            insecure_cookies = []
            
            print(f"   📊 Found {len(cookies)} cookie(s):")
            
            for i, cookie in enumerate(cookies):
                analysis = {
                    'index': i + 1,
                    'secure': 'secure' in cookie.lower(),
                    'httponly': 'httponly' in cookie.lower(),
                    'samesite': self.extract_samesite(cookie),
                    'has_path': 'path=' in cookie.lower(),
                    'has_domain': 'domain=' in cookie.lower(),
                    'has_maxage': 'max-age=' in cookie.lower() or 'expires=' in cookie.lower(),
                    'has_prefix': self.has_secure_prefix(cookie)
                }
                
                cookie_analysis.append(analysis)
                
                # Check for security issues
                issues = []
                if not analysis['secure'] and self.parsed_url.scheme == 'https':
                    issues.append("Missing Secure flag")
                if not analysis['httponly']:
                    issues.append("Missing HttpOnly flag")
                if not analysis['samesite']:
                    issues.append("Missing SameSite attribute")
                if not analysis['has_prefix'] and analysis['secure']:
                    issues.append("Missing __Secure- or __Host- prefix")
                
                if issues:
                    insecure_cookies.append(f"Cookie {i+1}: {', '.join(issues)}")
                    print(f"      ❌ Cookie {i+1}: {', '.join(issues)}")
                else:
                    print(f"      ✅ Cookie {i+1}: Secure")
            
            self.results['cookie_analysis'] = {
                'total_cookies': len(cookies),
                'secure_cookies': sum(1 for c in cookie_analysis if c['secure']),
                'httponly_cookies': sum(1 for c in cookie_analysis if c['httponly']),
                'samesite_cookies': sum(1 for c in cookie_analysis if c['samesite']),
                'insecure_cookies': len(insecure_cookies)
            }
            
            if insecure_cookies:
                self.vulnerabilities.extend(insecure_cookies)
                
        else:
            print("   ℹ️  No Set-Cookie headers found")
            self.results['cookie_analysis'] = {'total_cookies': 0}
    
    def extract_samesite(self, cookie):
        """Extract SameSite value from cookie"""
        cookie_lower = cookie.lower()
        
        if 'samesite=strict' in cookie_lower:
            return 'Strict'
        elif 'samesite=lax' in cookie_lower:
            return 'Lax'
        elif 'samesite=none' in cookie_lower:
            return 'None'
        else:
            return None
    
    def has_secure_prefix(self, cookie):
        """Check if cookie has secure prefix"""
        return '__secure-' in cookie.lower() or '__host-' in cookie.lower()
    
    def analyze_cors_configuration(self):
        """Analyze CORS configuration"""
        print("\n4️⃣  [CORS CONFIGURATION] Testing Cross-Origin Resource Sharing")
        
        # Test various origins
        test_origins = [
            ('http://evil.com', 'External malicious'),
            ('https://attacker.com', 'HTTPS malicious'),
            ('http://localhost:9999', 'Different port'),
            ('null', 'Null origin'),
            ('https://172.19.64.1.evil.com', 'Subdomain attack'),
            ('', 'No origin')
        ]
        
        cors_results = []
        vulnerabilities = []
        
        for origin, description in test_origins:
            headers = {'Origin': origin} if origin else {}
            
            try:
                # Test OPTIONS preflight
                resp = requests.options(
                    self.target_url,
                    headers=headers,
                    timeout=3,
                    verify=False
                )
                
                if 'access-control-allow-origin' in resp.headers:
                    allowed = resp.headers['access-control-allow-origin']
                    
                    if allowed == '*':
                        print(f"   🚨 CORS wildcard (*) allows {description}")
                        vulnerabilities.append(f"CORS wildcard allows {description}")
                        cors_results.append({
                            'origin': origin,
                            'allowed': allowed,
                            'risk': 'CRITICAL'
                        })
                    elif allowed == origin:
                        print(f"   ⚠️  CORS allows specific {description}")
                        vulnerabilities.append(f"CORS allows {description}")
                        cors_results.append({
                            'origin': origin,
                            'allowed': allowed,
                            'risk': 'HIGH'
                        })
                    else:
                        cors_results.append({
                            'origin': origin,
                            'allowed': allowed,
                            'risk': 'LOW'
                        })
                
                # Check for credentials
                if 'access-control-allow-credentials' in resp.headers:
                    if resp.headers['access-control-allow-credentials'].lower() == 'true':
                        print(f"   ⚠️  CORS with credentials for {description}")
                        vulnerabilities.append(f"CORS with credentials for {description}")
                        
            except Exception as e:
                pass
        
        self.results['cors_analysis'] = cors_results
        self.vulnerabilities.extend(vulnerabilities[:5])  # Add first 5
        
        if not cors_results:
            print("   ✅ No CORS misconfigurations detected")
    
    def analyze_information_disclosure(self):
        """Check for information disclosure in headers"""
        print("\n5️⃣  [INFORMATION DISCLOSURE] Checking for sensitive info leaks")
        
        # Headers that reveal server/technology information
        info_headers = [
            ('Server', 'Web server software'),
            ('X-Powered-By', 'Technology stack'),
            ('X-AspNet-Version', 'ASP.NET version'),
            ('X-AspNetMvc-Version', 'ASP.NET MVC version'),
            ('X-Runtime', 'Runtime information'),
            ('X-Debug-Token', 'Debug information'),
            ('X-Generator', 'CMS/generator'),
            ('X-Drupal-Cache', 'Drupal cache'),
            ('X-Varnish', 'Varnish cache'),
            ('Via', 'Proxy information'),
            ('X-Cache', 'Cache status'),
        ]
        
        disclosed_info = []
        
        for header, description in info_headers:
            if header in self.headers:
                value = self.headers[header]
                disclosed_info.append(f"{header}: {value}")
                
                # Check for version information
                if any(char in value for char in ['/', 'v', 'version', 'release']):
                    print(f"   📢 {header}: {value} (version information)")
                    self.vulnerabilities.append(f"{header} discloses version: {value}")
                else:
                    print(f"   ℹ️  {header}: {value}")
        
        # Check response body for sensitive information
        print("\n   🔍 Checking response body for sensitive data...")
        
        sensitive_patterns = [
            ('password', 'Password in response'),
            ('token', 'Token in response'),
            ('secret', 'Secret in response'),
            ('api_key', 'API key in response'),
            ('debug', 'Debug information'),
            ('stack trace', 'Stack trace'),
            ('error at', 'Error details'),
            ('sql', 'SQL information'),
            ('exception', 'Exception details'),
            ('config', 'Configuration'),
            ('env', 'Environment variables'),
        ]
        
        body_text = self.response.text.lower()
        
        for pattern, description in sensitive_patterns:
            if pattern in body_text:
                print(f"   🚨 {description} found in response body")
                self.vulnerabilities.append(f"Body contains {description}")
        
        self.results['information_disclosure'] = {
            'headers_disclosed': len(disclosed_info),
            'sensitive_patterns_found': len([p for p, d in sensitive_patterns if p in body_text])
        }
        
        if not disclosed_info:
            print("   ✅ No information disclosure in headers")
    
    def analyze_transport_security(self):
        """Analyze transport layer security"""
        print("\n6️⃣  [TRANSPORT SECURITY] Testing HTTPS/TLS configuration")
        
        if self.parsed_url.scheme == 'http':
            print("   ⚠️  Site loaded over HTTP (not HTTPS)")
            self.vulnerabilities.append("Using HTTP instead of HTTPS")
            
            # Check if HTTPS is available
            https_url = self.target_url.replace('http://', 'https://')
            try:
                https_resp = requests.get(https_url, timeout=5, verify=False)
                if https_resp.status_code < 400:
                    print(f"   ℹ️  HTTPS version available at {https_url}")
                    self.results['https_available'] = True
            except:
                self.results['https_available'] = False
        
        elif self.parsed_url.scheme == 'https':
            print("   ✅ Using HTTPS")
            
            # Test SSL/TLS configuration
            try:
                hostname = self.parsed_url.hostname
                port = self.parsed_url.port or 443
                
                context = ssl.create_default_context()
                
                # Test various TLS versions
                tls_versions = {
                    ssl.PROTOCOL_TLSv1_2: 'TLSv1.2',
                    ssl.PROTOCOL_TLSv1_3: 'TLSv1.3'
                }
                
                supported_versions = []
                
                for proto, name in tls_versions.items():
                    try:
                        context = ssl.SSLContext(proto)
                        with socket.create_connection((hostname, port), timeout=3) as sock:
                            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                                cipher = ssock.cipher()
                                if cipher:
                                    supported_versions.append(name)
                    except:
                        pass
                
                if supported_versions:
                    print(f"   🔐 Supported TLS versions: {', '.join(supported_versions)}")
                    
                    if 'TLSv1.3' in supported_versions:
                        print("   ✅ TLSv1.3 supported (most secure)")
                    elif 'TLSv1.2' in supported_versions:
                        print("   ⚠️  Only TLSv1.2 supported (consider enabling TLSv1.3)")
                    else:
                        print("   🚨 Only old TLS versions supported")
                        self.vulnerabilities.append("Only old TLS versions supported")
                
                # Check certificate
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        from datetime import datetime
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_remaining = (not_after - datetime.now()).days
                        
                        print(f"   📅 Certificate expires in {days_remaining} days")
                        
                        if days_remaining < 30:
                            print("   ⚠️  Certificate expires soon")
                            self.vulnerabilities.append(f"Certificate expires in {days_remaining} days")
                
                self.results['tls_analysis'] = {
                    'supported_versions': supported_versions,
                    'certificate_valid': True,
                    'days_remaining': days_remaining
                }
                
            except Exception as e:
                print(f"   ❌ TLS/SSL check failed: {e}")
                self.results['tls_analysis'] = {'error': str(e)}
    
    def analyze_cross_origin_policies(self):
        """Analyze cross-origin isolation headers"""
        print("\n7️⃣  [CROSS-ORIGIN POLICIES] Testing isolation headers")
        
        coop_headers = [
            ('Cross-Origin-Opener-Policy', ['same-origin', 'same-origin-allow-popups']),
            ('Cross-Origin-Embedder-Policy', ['require-corp']),
            ('Cross-Origin-Resource-Policy', ['same-origin', 'same-site'])
        ]
        
        results = []
        
        for header, recommended in coop_headers:
            if header in self.headers:
                value = self.headers[header]
                
                if value in recommended:
                    print(f"   ✅ {header}: {value}")
                    results.append({
                        'header': header,
                        'value': value,
                        'status': 'SECURE'
                    })
                else:
                    print(f"   ⚠️  {header}: {value} (recommended: {', '.join(recommended)})")
                    self.vulnerabilities.append(f"{header} weak value: {value}")
                    results.append({
                        'header': header,
                        'value': value,
                        'status': 'WEAK'
                    })
            else:
                print(f"   ❌ Missing {header}")
                results.append({
                    'header': header,
                    'value': None,
                    'status': 'MISSING'
                })
        
        self.results['cross_origin_policies'] = results
    
    def analyze_cache_control(self):
        """Analyze cache control headers"""
        print("\n8️⃣  [CACHE CONTROL] Testing caching of sensitive data")
        
        if 'Cache-Control' in self.headers:
            cache_control = self.headers['Cache-Control'].lower()
            
            # Check if current URL might contain sensitive data
            sensitive_paths = ['/api/', '/auth/', '/admin/', '/user/', '/profile/']
            is_sensitive = any(path in self.final_url for path in sensitive_paths)
            
            safe_directives = ['no-store', 'no-cache', 'private', 'max-age=0']
            has_safe = any(directive in cache_control for directive in safe_directives)
            
            if is_sensitive:
                if has_safe:
                    print(f"   ✅ Sensitive endpoint properly cached: {cache_control}")
                    self.results['cache_control'] = {'status': 'SECURE', 'value': cache_control}
                else:
                    print(f"   🚨 Sensitive endpoint may be cached: {cache_control}")
                    self.vulnerabilities.append(f"Sensitive data may be cached: {cache_control}")
                    self.results['cache_control'] = {'status': 'VULNERABLE', 'value': cache_control}
            else:
                print(f"   ℹ️  Cache-Control: {cache_control}")
                self.results['cache_control'] = {'status': 'OK', 'value': cache_control}
        else:
            print("   ❌ No Cache-Control header")
            self.results['cache_control'] = {'status': 'MISSING'}
    
    def analyze_misc_headers(self):
        """Analyze miscellaneous security headers"""
        print("\n9️⃣  [MISCELLANEOUS] Other security headers")
        
        misc_headers = [
            ('X-Download-Options', 'noopen', 'Prevents file open attacks (IE)'),
            ('X-Permitted-Cross-Domain-Policies', 'none', 'Flash/PDF cross-domain policy'),
            ('X-Robots-Tag', None, 'Search engine indexing control'),
            ('Pragma', 'no-cache', 'HTTP/1.0 cache control'),
            ('Expires', '-1', 'Cache expiration'),
            ('Clear-Site-Data', None, 'Data clearing directive'),
            ('Expect-CT', None, 'Certificate Transparency'),
        ]
        
        results = []
        
        for header, recommended, description in misc_headers:
            if header in self.headers:
                value = self.headers[header]
                
                if recommended and recommended in value.lower():
                    print(f"   ✅ {header}: {value[:40]}... - {description}")
                    results.append({
                        'header': header,
                        'status': 'SECURE',
                        'value': value
                    })
                else:
                    print(f"   ℹ️  {header}: {value[:40]}... - {description}")
                    results.append({
                        'header': header,
                        'status': 'PRESENT',
                        'value': value
                    })
            else:
                print(f"   ❌ Missing {header} - {description}")
                results.append({
                    'header': header,
                    'status': 'MISSING'
                })
        
        self.results['misc_headers'] = results
    
    def generate_report(self):
        """Generate comprehensive security report"""
        print("\n" + "=" * 100)
        print("📊 SECURITY HEADERS COMPREHENSIVE REPORT")
        print("=" * 100)
        
        # Calculate scores
        total_checks = 9
        passed_checks = sum(1 for key in self.results if 'status' not in str(self.results.get(key, {})).lower())
        
        # Weight vulnerabilities
        critical_vulns = len([v for v in self.vulnerabilities if 'CRITICAL' in v or 'Missing Content-Security-Policy' in v])
        high_vulns = len([v for v in self.vulnerabilities if 'HIGH' in v and 'CRITICAL' not in v])
        medium_vulns = len([v for v in self.vulnerabilities if 'MEDIUM' in v])
        low_vulns = len([v for v in self.vulnerabilities if 'LOW' in v and 'MEDIUM' not in v and 'HIGH' not in v])
        
        security_score = 100 - ((critical_vulns * 15) + (high_vulns * 10) + (medium_vulns * 5) + (low_vulns * 2))
        security_score = max(0, min(100, security_score))
        
        # Report Header
        print(f"\n🎯 Target: {self.target_url}")
        print(f"📅 Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"⏱️  Duration: {time.time() - self.start_time:.1f} seconds")
        print("\n" + "-" * 100)
        
        # Security Score
        print(f"\n📈 OVERALL SECURITY SCORE: {security_score:.1f}%")
        
        if security_score >= 90:
            print("   🏆 EXCELLENT - Strong security headers")
        elif security_score >= 70:
            print("   👍 GOOD - Minor improvements needed")
        elif security_score >= 50:
            print("   ⚠️  FAIR - Significant improvements needed")
        else:
            print("   🚨 POOR - Critical issues found")
        
        # Vulnerability Summary
        print(f"\n⚠️  VULNERABILITY SUMMARY:")
        print(f"   🔴 Critical: {critical_vulns}")
        print(f"   🟠 High: {high_vulns}")
        print(f"   🟡 Medium: {medium_vulns}")
        print(f"   🔵 Low: {low_vulns}")
        print(f"   ✅ Checks Passed: {passed_checks}/{total_checks}")
        
        # Detailed Findings
        if self.vulnerabilities:
            print(f"\n🔍 DETAILED FINDINGS (Top 20):")
            for i, vuln in enumerate(self.vulnerabilities[:20], 1):
                print(f"   {i}. {vuln}")
            
            if len(self.vulnerabilities) > 20:
                print(f"   ... and {len(self.vulnerabilities) - 20} more issues")
        else:
            print(f"\n✅ No security header issues detected!")
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        
        # Critical recommendations
        if critical_vulns > 0:
            print("   1. 🚨 ADDRESS CRITICAL ISSUES IMMEDIATELY")
        
        # Specific recommendations based on findings
        if 'basic_headers' in self.results:
            basic = self.results['basic_headers']
            if basic.get('missing', 0) > 0:
                print("   2. 🔒 Implement missing security headers:")
                
                if 'Content-Security-Policy' not in str(self.headers):
                    print("      • Content-Security-Policy: default-src 'self';")
                if 'X-Frame-Options' not in str(self.headers):
                    print("      • X-Frame-Options: DENY")
                if 'X-Content-Type-Options' not in str(self.headers):
                    print("      • X-Content-Type-Options: nosniff")
        
        if 'cookie_analysis' in self.results:
            cookies = self.results['cookie_analysis']
            if cookies.get('insecure_cookies', 0) > 0:
                print("   3. 🍪 Secure your cookies:")
                print("      • Add Secure, HttpOnly, and SameSite attributes")
                print("      • Consider __Host- and __Secure- prefixes")
        
        if self.parsed_url.scheme == 'http':
            print("   4. 🔐 Enforce HTTPS:")
            print("      • Redirect HTTP to HTTPS")
            print("      • Implement HSTS header")
        
        # Always include these
        print("   5. 📋 Next steps:")
        print("      • Implement CSP with reporting")
        print("      • Regularly update headers")
        print("      • Monitor security headers with automated tools")
        
        # Save results
        self.save_results()
    
    def save_results(self):
        """Save test results to file"""
        try:
            results_data = {
                'target': self.target_url,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'duration': time.time() - self.start_time,
                'headers_found': dict(self.headers),
                'results': self.results,
                'vulnerabilities': self.vulnerabilities
            }
            
            with open('security_headers_results.json', 'w') as f:
                json.dump(results_data, f, indent=2)
            
            print(f"\n💾 Results saved to security_headers_results.json")
            
        except Exception as e:
            print(f"\n⚠️  Could not save results: {e}")
    
    def run_all_tests(self):
        """Run all security header tests"""
        self.print_banner()
        
        if not self.connect():
            print("❌ Cannot proceed without connection")
            return
        
        # Run all analysis functions
        tests = [
            self.analyze_basic_headers,
            self.analyze_csp_detailed,
            self.analyze_cookie_security,
            self.analyze_cors_configuration,
            self.analyze_information_disclosure,
            self.analyze_transport_security,
            self.analyze_cross_origin_policies,
            self.analyze_cache_control,
            self.analyze_misc_headers
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                print(f"❌ Test failed: {e}")
        
        # Generate final report
        self.generate_report()

def main():
    """Main function"""
    tester = SecurityHeadersTester(TARGET)
    tester.run_all_tests()

if __name__ == "__main__":
    main()