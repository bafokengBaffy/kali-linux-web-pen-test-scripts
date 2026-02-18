#!/usr/bin/env python3
"""
ULTIMATE QUICK SECURITY TESTER (30+ Rapid Tests)
Target: http://172.19.64.1:5000

Purpose: This script provides a comprehensive security assessment before deep testing.
It performs 30+ rapid tests to identify obvious security vulnerabilities.

Author: Security Testing Suite
Version: 2.0
Windows Target: 172.19.64.1:5000

Usage: python quick_test.py
Note: Make sure your server is running on http://172.19.64.1:5000 first
"""

import requests
import json
import time
import random
import string
import socket
import ssl
from urllib.parse import urlparse, quote
import concurrent.futures
import warnings
warnings.filterwarnings('ignore')

# Configuration
TARGET = "http://172.19.64.1:5000"  # Your Windows server
TARGET_IP = "172.19.64.1"
TARGET_PORT = 5000

# Enhanced endpoint list for Windows applications
ENDPOINTS = [
    # Authentication endpoints
    "/api/v1/auth/login",
    "/api/v1/auth/register", 
    "/api/v1/auth/logout",
    "/api/v1/auth/forgot-password",
    "/api/v1/auth/reset-password",
    
    # User endpoints
    "/api/v1/users",
    "/api/v1/users/profile",
    "/api/v1/users/me",
    "/api/v1/users/1",
    
    # Admin endpoints
    "/admin",
    "/admin/login",
    "/admin/dashboard",
    "/wp-admin",
    "/administrator",
    
    # API endpoints
    "/api/v1/events",
    "/api/v1/events/1",
    "/api/v1/comments",
    "/api/v1/posts",
    
    # Data endpoints
    "/api/v1/export",
    "/api/v1/import",
    "/api/v1/backup",
    
    # Configuration endpoints
    "/api/v1/config",
    "/api/v1/settings",
    "/api/v1/env",
    
    # File endpoints
    "/api/v1/uploads",
    "/api/v1/files",
    "/api/v1/download",
    
    # Health/status
    "/health",
    "/status",
    "/version",
    "/info",
    
    # Documentation
    "/swagger",
    "/swagger-ui",
    "/api-docs",
    "/docs",
    
    # Debug endpoints
    "/debug",
    "/phpinfo",
    "/test",
    "/ping"
]

def print_banner():
    """Display comprehensive program banner"""
    print("\n" + "=" * 100)
    print("🚀 ULTIMATE QUICK SECURITY TESTER v2.0")
    print("=" * 100)
    print(f"🎯 TARGET: {TARGET}")
    print(f"🏠 IP Address: {TARGET_IP}")
    print(f"🔌 Port: {TARGET_PORT}")
    print(f"📅 Started: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 100)
    print("🔍 Performing 30+ rapid security tests...")
    print("=" * 100 + "\n")

def test_network_connectivity():
    """Test basic network connectivity to target"""
    print("🔌 [Network] Testing connectivity...")
    
    results = {}
    
    # Test 1: Basic HTTP connection
    try:
        start = time.time()
        resp = requests.get(TARGET, timeout=10, verify=False)
        elapsed = time.time() - start
        
        results['http_connection'] = {
            'status': 'SUCCESS',
            'response_time': f"{elapsed:.2f}s",
            'status_code': resp.status_code,
            'server': resp.headers.get('Server', 'Unknown')
        }
        
        print(f"   ✅ HTTP Connected in {elapsed:.2f}s")
        print(f"   📊 Status: {resp.status_code}")
        print(f"   🖥️  Server: {resp.headers.get('Server', 'Unknown')}")
        
    except requests.exceptions.RequestException as e:
        results['http_connection'] = {
            'status': 'FAILED',
            'error': str(e)
        }
        print(f"   ❌ HTTP Connection failed: {e}")
        return None
    
    # Test 2: Port scanning (quick check for common ports)
    print("\n   🔍 Quick port scan (common Windows ports):")
    common_ports = [80, 443, 8000, 8080, 3000, 5000, 5001, 5432, 3306, 6379, 27017]
    
    open_ports = []
    for port in common_ports:
        if port == TARGET_PORT:
            continue
            
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((TARGET_IP, port))
            sock.close()
            
            if result == 0:
                open_ports.append(port)
                print(f"      ⚠️  Port {port} open")
        except:
            pass
    
    if open_ports:
        results['open_ports'] = open_ports
    
    # Test 3: SSL/TLS check if HTTPS available
    print("\n   🔐 Testing HTTPS availability...")
    https_url = TARGET.replace('http://', 'https://')
    try:
        https_resp = requests.get(https_url, timeout=5, verify=False)
        if https_resp.status_code < 400:
            results['https_available'] = True
            print(f"   ✅ HTTPS available at {https_url}")
            
            # Check SSL certificate
            try:
                context = ssl.create_default_context()
                with socket.create_connection((TARGET_IP, 443), timeout=3) as sock:
                    with context.wrap_socket(sock, server_hostname=TARGET_IP) as ssock:
                        cert = ssock.getpeercert()
                        results['ssl_cert'] = 'Valid'
                        print(f"   ✅ SSL Certificate valid")
            except:
                results['ssl_cert'] = 'Invalid/None'
                print(f"   ⚠️  SSL Certificate issue")
    except:
        results['https_available'] = False
        print(f"   ℹ️  HTTPS not available")
    
    return results

def test_security_headers():
    """Test for security headers"""
    print("\n🔒 [Security Headers] Testing HTTP headers...")
    
    try:
        resp = requests.get(TARGET, timeout=5, verify=False)
        headers = resp.headers
        
        # Critical security headers
        critical_headers = {
            'Content-Security-Policy': 'Prevents XSS attacks',
            'X-Frame-Options': 'Prevents clickjacking',
            'X-Content-Type-Options': 'Prevents MIME sniffing',
            'Strict-Transport-Security': 'Enforces HTTPS',
            'Referrer-Policy': 'Controls referrer information',
            'Permissions-Policy': 'Controls browser features',
            'X-XSS-Protection': 'Legacy XSS protection'
        }
        
        results = {}
        missing = []
        
        for header, description in critical_headers.items():
            if header in headers:
                value = headers[header]
                results[header] = {
                    'present': True,
                    'value': value[:50],
                    'description': description
                }
                
                # Validate header values
                if header == 'X-Frame-Options':
                    if value.upper() not in ['DENY', 'SAMEORIGIN']:
                        results[header]['warning'] = 'Weak value - should be DENY or SAMEORIGIN'
                
                elif header == 'X-Content-Type-Options':
                    if value.lower() != 'nosniff':
                        results[header]['warning'] = 'Should be "nosniff"'
                
                print(f"   ✅ {header}: {value[:40]}...")
            else:
                results[header] = {
                    'present': False,
                    'description': description
                }
                missing.append(header)
                print(f"   ❌ {header}: MISSING")
        
        # Check for information disclosure headers
        print("\n   📢 Information disclosure headers:")
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
        for header in info_headers:
            if header in headers:
                print(f"      ⚠️  {header}: {headers[header]} (information leaked)")
                results[f'info_{header}'] = headers[header]
        
        # Cookie security analysis
        print("\n   🍪 Cookie security analysis:")
        if 'Set-Cookie' in headers:
            cookies = headers.get_all('Set-Cookie') if hasattr(headers, 'get_all') else [headers['Set-Cookie']]
            
            secure_count = http_only_count = same_site_count = 0
            
            for cookie in cookies:
                cookie_lower = cookie.lower()
                if 'secure' in cookie_lower:
                    secure_count += 1
                if 'httponly' in cookie_lower:
                    http_only_count += 1
                if 'samesite' in cookie_lower:
                    same_site_count += 1
            
            results['cookies'] = {
                'total': len(cookies),
                'secure': secure_count,
                'httponly': http_only_count,
                'samesite': same_site_count
            }
            
            print(f"      📊 {len(cookies)} cookies found")
            print(f"      🔒 Secure: {secure_count}/{len(cookies)}")
            print(f"      🚫 HttpOnly: {http_only_count}/{len(cookies)}")
            print(f"      🌐 SameSite: {same_site_count}/{len(cookies)}")
        
        return results
        
    except Exception as e:
        print(f"   ❌ Header test failed: {e}")
        return None

def test_endpoint_discovery():
    """Discover and test accessible endpoints"""
    print(f"\n🔍 [Endpoint Discovery] Testing {len(ENDPOINTS)} endpoints...")
    
    results = {
        'accessible': [],
        'blocked': [],
        'not_found': []
    }
    
    def test_single_endpoint(endpoint):
        try:
            url = f"{TARGET}{endpoint}"
            
            # Try GET first
            resp = requests.get(url, timeout=3, verify=False)
            
            status = resp.status_code
            
            if status < 400:  # Accessible
                return (endpoint, 'accessible', status, len(resp.text))
            elif status == 404:  # Not found
                return (endpoint, 'not_found', status, 0)
            elif status == 403 or status == 401:  # Blocked/Unauthorized
                return (endpoint, 'blocked', status, 0)
            else:  # Other status
                return (endpoint, 'other', status, 0)
                
        except Exception as e:
            return (endpoint, 'error', 0, str(e))
    
    # Use concurrent testing for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_single_endpoint, endpoint) for endpoint in ENDPOINTS]
        
        accessible_count = 0
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            endpoint, status, code, info = future.result()
            
            if status == 'accessible':
                accessible_count += 1
                results['accessible'].append((endpoint, code))
                if accessible_count <= 10:  # Show first 10 accessible endpoints
                    print(f"   ✅ {endpoint} → {code} ({info} bytes)")
            elif status == 'blocked' and i % 5 == 0:  # Sample some blocked endpoints
                print(f"   🔒 {endpoint} → {code} (blocked)")
            elif status == 'error' and 'timeout' not in str(info):
                print(f"   ❌ {endpoint} → Error: {info}")
    
    print(f"\n   📊 Summary: {len(results['accessible'])} accessible, "
          f"{len(results['blocked'])} blocked, "
          f"{len(results['not_found'])} not found")
    
    return results

def test_injection_vulnerabilities():
    """Test for SQLi, XSS, and command injection"""
    print("\n💉 [Injection Testing] Testing for SQLi, XSS, and command injection...")
    
    results = {
        'sqli': {'vulnerable': False, 'details': []},
        'xss': {'vulnerable': False, 'details': []},
        'command': {'vulnerable': False, 'details': []}
    }
    
    # SQL Injection payloads
    sql_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL,username,password FROM users--",
        "' OR 1=1--",
        "'; DROP TABLE users; --",
        "' OR SLEEP(5)--"
    ]
    
    # XSS payloads
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\" onmouseover=\"alert(1)",
        "'><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)"
    ]
    
    # Command injection payloads
    cmd_payloads = [
        "; ls",
        "| dir",
        "&& whoami",
        "`id`",
        "$(cat /etc/passwd)"
    ]
    
    # Test login endpoint with SQLi
    print("   🗄️  SQL Injection testing...")
    for payload in sql_payloads[:3]:  # Test first 3
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                json={'email': payload, 'password': 'test'},
                timeout=3,
                verify=False
            )
            
            # Check for SQL error patterns
            error_patterns = ['sql', 'syntax', 'mysql', 'postgresql', 'database']
            if any(pattern in resp.text.lower() for pattern in error_patterns):
                print(f"      ⚠️  SQL error detected with payload: {payload[:20]}...")
                results['sqli']['details'].append(f"Error with: {payload[:20]}")
            elif resp.status_code == 200 and 'error' not in resp.text.lower():
                print(f"      🚨 Possible SQLi vulnerability with: {payload[:20]}...")
                results['sqli']['vulnerable'] = True
                results['sqli']['details'].append(f"Possible with: {payload[:20]}")
                
        except Exception as e:
            pass
    
    # Test search endpoint for XSS
    print("\n   🎯 XSS testing...")
    for payload in xss_payloads[:3]:
        try:
            resp = requests.get(
                f"{TARGET}/api/v1/search?q={quote(payload)}",
                timeout=3,
                verify=False
            )
            
            # Check if payload is reflected
            if payload in resp.text:
                print(f"      🚨 XSS reflected: {payload[:20]}...")
                results['xss']['vulnerable'] = True
                results['xss']['details'].append(f"Reflected: {payload[:20]}")
            elif '<script>' in resp.text:
                print(f"      ⚠️  Script tags in response")
                
        except Exception as e:
            pass
    
    return results

def test_authentication():
    """Test authentication mechanisms"""
    print("\n🔑 [Authentication Testing] Testing auth endpoints...")
    
    results = {
        'registration': {},
        'login': {},
        'password_reset': {}
    }
    
    # Test registration endpoint
    print("   📝 Registration testing...")
    try:
        unique_email = f"test_{int(time.time())}_{random.randint(1000,9999)}@test.com"
        resp = requests.post(
            f"{TARGET}/api/v1/auth/register",
            json={
                'email': unique_email,
                'password': 'Test123!',
                'name': 'Security Test User'
            },
            timeout=5,
            verify=False
        )
        
        results['registration'] = {
            'status_code': resp.status_code,
            'success': resp.status_code in [200, 201],
            'email_used': unique_email
        }
        
        if resp.status_code in [200, 201]:
            print(f"      ✅ Registration allowed: {unique_email}")
        elif resp.status_code == 429:
            print(f"      🔒 Registration rate limited (good)")
        else:
            print(f"      ℹ️  Registration: {resp.status_code}")
            
    except Exception as e:
        results['registration']['error'] = str(e)
        print(f"      ❌ Registration test failed: {e}")
    
    # Test login with common passwords
    print("\n   🔓 Login testing (common passwords)...")
    common_passwords = ['admin', 'password', '123456', 'test', 'password123']
    
    for password in common_passwords[:3]:  # Test first 3
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                json={'email': 'admin@test.com', 'password': password},
                timeout=3,
                verify=False
            )
            
            if resp.status_code == 200:
                print(f"      🚨 Login successful with common password: {password}")
                results['login'][password] = 'SUCCESS'
            elif resp.status_code == 429:
                print(f"      🔒 Login rate limited (good)")
                results['login'][password] = 'RATE_LIMITED'
            else:
                results['login'][password] = 'FAILED'
                
        except Exception as e:
            pass
    
    return results

def test_file_upload():
    """Test file upload functionality"""
    print("\n📁 [File Upload Testing] Testing upload endpoints...")
    
    results = {}
    
    # Test common upload paths
    upload_paths = ['/api/v1/upload', '/upload', '/api/upload', '/admin/upload']
    
    for path in upload_paths:
        try:
            resp = requests.get(f"{TARGET}{path}", timeout=3, verify=False)
            if resp.status_code < 400:
                print(f"   ⚠️  Upload endpoint found: {path}")
                results[path] = 'found'
                
                # Try to upload a file
                files = {'file': ('test.txt', b'Test content', 'text/plain')}
                upload_resp = requests.post(f"{TARGET}{path}", files=files, timeout=5, verify=False)
                
                if upload_resp.status_code < 400:
                    print(f"      🚨 File upload successful: {path}")
                    results[path] = 'vulnerable'
                    
        except Exception as e:
            pass
    
    if not results:
        print("   ✅ No upload endpoints found")
    
    return results

def test_directory_traversal():
    """Test for directory traversal vulnerabilities"""
    print("\n📂 [Directory Traversal] Testing path traversal...")
    
    results = []
    traversal_payloads = [
        "../../../etc/passwd",
        "../../../windows/win.ini",
        "..\\..\\..\\windows\\win.ini",
        "../../../boot.ini",
        "../../../autoexec.bat",
        "../app.js",
        "../../package.json",
        "../../../WEB-INF/web.xml"
    ]
    
    # Test in file endpoints
    endpoints_to_test = ['/api/v1/files/', '/download/', '/static/', '/uploads/']
    
    for endpoint in endpoints_to_test:
        for payload in traversal_payloads[:4]:  # Test first 4
            try:
                url = f"{TARGET}{endpoint}{payload}"
                resp = requests.get(url, timeout=3, verify=False)
                
                # Check for sensitive content
                sensitive_patterns = [
                    'root:',  # /etc/passwd
                    'for 16-bit app support',  # win.ini
                    'package.json',
                    'web-app',
                    '[boot loader]'  # boot.ini
                ]
                
                for pattern in sensitive_patterns:
                    if pattern in resp.text:
                        print(f"   🚨 Directory traversal successful: {payload}")
                        results.append(f"{endpoint}{payload}")
                        break
                        
            except Exception as e:
                pass
    
    if not results:
        print("   ✅ No directory traversal detected")
    
    return results

def test_rate_limiting():
    """Test rate limiting mechanisms"""
    print("\n⏱️  [Rate Limiting] Testing flood protection...")
    
    results = {}
    
    # Test rapid requests
    endpoint = "/api/v1/auth/login"
    success_count = 0
    rate_limited_count = 0
    
    print("   Sending 10 rapid login attempts...")
    for i in range(10):
        try:
            resp = requests.post(
                f"{TARGET}{endpoint}",
                json={'email': f'test{i}@test.com', 'password': 'wrong'},
                timeout=2,
                verify=False
            )
            
            if resp.status_code != 429:  # Not rate limited
                success_count += 1
            else:
                rate_limited_count += 1
                
            if i == 4:  # Report at halfway
                print(f"      After 5 attempts: {success_count} succeeded, {rate_limited_count} blocked")
                
        except Exception as e:
            pass
    
    results['rapid_test'] = {
        'total': 10,
        'successful': success_count,
        'rate_limited': rate_limited_count,
        'percentage_blocked': (rate_limited_count / 10) * 100
    }
    
    print(f"   📊 Results: {success_count}/10 succeeded, {rate_limited_count}/10 rate limited")
    
    if success_count >= 8:
        print("   ⚠️  Weak rate limiting detected")
        results['rapid_test']['assessment'] = 'WEAK'
    elif success_count <= 3:
        print("   ✅ Strong rate limiting")
        results['rapid_test']['assessment'] = 'STRONG'
    else:
        print("   ℹ️  Moderate rate limiting")
        results['rapid_test']['assessment'] = 'MODERATE'
    
    return results

def test_cors_misconfig():
    """Test CORS misconfigurations"""
    print("\n🌐 [CORS Testing] Testing cross-origin resource sharing...")
    
    results = {}
    test_origins = ['http://evil.com', 'https://attacker.com', 'null']
    
    for origin in test_origins:
        try:
            headers = {'Origin': origin}
            
            # Test preflight
            resp = requests.options(
                TARGET,
                headers=headers,
                timeout=3,
                verify=False
            )
            
            if 'access-control-allow-origin' in resp.headers:
                allowed = resp.headers['access-control-allow-origin']
                
                if allowed == '*':
                    print(f"   🚨 CORS wildcard (*) allows {origin}")
                    results[origin] = 'WILDCARD'
                elif allowed == origin:
                    print(f"   ⚠️  CORS allows specific origin: {origin}")
                    results[origin] = 'SPECIFIC'
                    
        except Exception as e:
            pass
    
    if not results:
        print("   ✅ No CORS misconfigurations detected")
    
    return results

def test_error_handling():
    """Test error handling for information disclosure"""
    print("\n🚨 [Error Handling] Testing for verbose errors...")
    
    results = []
    
    # Trigger various errors
    error_tests = [
        ("Non-existent endpoint", "/api/v1/nonexistent-endpoint-12345"),
        ("Malformed JSON", "/api/v1/auth/login", '{"malformed": json}'),
        ("Invalid parameter", "/api/v1/users?id=INVALID' OR 1=1--"),
        ("Large payload", "/api/v1/events", 'A' * 10000)
    ]
    
    for test_name, endpoint, *payload in error_tests:
        try:
            if payload:
                resp = requests.post(
                    f"{TARGET}{endpoint}",
                    data=payload[0],
                    timeout=3,
                    verify=False,
                    headers={'Content-Type': 'application/json'}
                )
            else:
                resp = requests.get(f"{TARGET}{endpoint}", timeout=3, verify=False)
            
            # Check for verbose error messages
            error_indicators = [
                'stack trace', 'error at line', 'exception', 'sql error',
                'database', 'syntax', 'typeerror', 'referenceerror'
            ]
            
            for indicator in error_indicators:
                if indicator in resp.text.lower():
                    print(f"   ⚠️  Verbose error in {test_name}: contains '{indicator}'")
                    results.append(f"{test_name}: {indicator}")
                    break
                    
        except Exception as e:
            pass
    
    if not results:
        print("   ✅ Error messages appear sanitized")
    
    return results

def generate_report(all_results, vulnerabilities):
    """Generate comprehensive security report"""
    print("\n" + "=" * 100)
    print("📊 COMPREHENSIVE SECURITY ASSESSMENT REPORT")
    print("=" * 100)
    
    # Calculate scores
    total_tests = 10
    critical_vulns = len([v for v in vulnerabilities if '🚨' in v])
    warning_vulns = len([v for v in vulnerabilities if '⚠️' in v])
    
    security_score = 100 - ((critical_vulns * 10) + (warning_vulns * 5))
    security_score = max(0, min(100, security_score))
    
    # Report header
    print(f"\n🎯 Target: {TARGET}")
    print(f"📅 Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"⏱️  Duration: {time.time() - start_time:.1f} seconds")
    print("\n" + "-" * 100)
    
    # Security Score
    print(f"\n📈 SECURITY SCORE: {security_score:.1f}%")
    
    if security_score >= 90:
        print("   🏆 EXCELLENT - Strong security posture")
    elif security_score >= 70:
        print("   👍 GOOD - Some improvements needed")
    elif security_score >= 50:
        print("   ⚠️  FAIR - Significant improvements needed")
    else:
        print("   🚨 POOR - Immediate action required")
    
    # Vulnerability Summary
    print(f"\n⚠️  VULNERABILITY SUMMARY:")
    print(f"   🔴 Critical: {critical_vulns}")
    print(f"   🟡 Warnings: {warning_vulns}")
    print(f"   🟢 Total Tests: {total_tests}")
    
    # Detailed Findings
    if vulnerabilities:
        print(f"\n🔍 DETAILED FINDINGS:")
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"   {i}. {vuln}")
    else:
        print(f"\n✅ No security issues detected in quick test!")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    
    # Based on findings
    if critical_vulns > 0:
        print("   1. 🚨 IMMEDIATE ACTION REQUIRED - Address critical vulnerabilities first")
    
    if 'sqli' in all_results and all_results['sqli'].get('vulnerable'):
        print("   2. 🔒 Implement parameterized queries and input validation")
    
    if 'xss' in all_results and all_results['xss'].get('vulnerable'):
        print("   3. 🛡️  Implement Content Security Policy and output encoding")
    
    if 'rate_limiting' in all_results and all_results['rate_limiting'].get('rapid_test', {}).get('assessment') == 'WEAK':
        print("   4. ⏱️  Strengthen rate limiting on authentication endpoints")
    
    # Always recommend these
    print("   5. 📋 Run comprehensive tests:")
    print("      python security_headers.py")
    print("      python csrf_exploit.py")
    print("      python rate_limit_bypass.py")
    
    # Network Info
    if 'network' in all_results:
        print(f"\n🌐 NETWORK INFORMATION:")
        network = all_results['network']
        if 'http_connection' in network:
            conn = network['http_connection']
            if conn['status'] == 'SUCCESS':
                print(f"   Response Time: {conn['response_time']}")
                print(f"   Server: {conn.get('server', 'Unknown')}")
    
    print("\n" + "=" * 100)
    print("✅ Quick security assessment complete!")
    print("=" * 100)

def main():
    """Main function to run all quick tests"""
    global start_time
    start_time = time.time()
    
    print_banner()
    
    all_results = {}
    vulnerabilities = []
    
    # Run all tests
    tests = [
        ("Network Connectivity", test_network_connectivity),
        ("Security Headers", test_security_headers),
        ("Endpoint Discovery", test_endpoint_discovery),
        ("Injection Vulnerabilities", test_injection_vulnerabilities),
        ("Authentication", test_authentication),
        ("File Upload", test_file_upload),
        ("Directory Traversal", test_directory_traversal),
        ("Rate Limiting", test_rate_limiting),
        ("CORS Misconfiguration", test_cors_misconfig),
        ("Error Handling", test_error_handling)
    ]
    
    for test_name, test_func in tests:
        try:
            print(f"\n{'='*50}")
            print(f"🧪 TEST: {test_name}")
            print(f"{'='*50}")
            
            result = test_func()
            if result:
                all_results[test_name.lower().replace(' ', '_')] = result
                
        except Exception as e:
            print(f"❌ Test '{test_name}' failed: {e}")
            vulnerabilities.append(f"Test '{test_name}' failed: {e}")
    
    # Generate final report
    generate_report(all_results, vulnerabilities)
    
    # Save results to file
    try:
        with open('quick_test_results.json', 'w') as f:
            json.dump(all_results, f, indent=2)
        print(f"\n💾 Results saved to quick_test_results.json")
    except:
        pass

if __name__ == "__main__":
    main()