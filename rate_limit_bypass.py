#!/usr/bin/env python3
"""
ADVANCED RATE LIMIT BYPASS TESTER

Purpose: This script tests for rate limit bypass vulnerabilities using 15+ techniques.
Rate limiting protects against brute force attacks, but can often be bypassed
using various techniques like IP rotation, slow attacks, and concurrent flooding.

Author: Security Testing Script
Version: 2.0
Date: 2024

Usage: python rate_limit_bypass.py
Note: Update the TARGET variable with your target server URL before running
"""

import requests
import time
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed

# ============================================================================
# CONFIGURATION SECTION - UPDATE THESE VALUES FOR YOUR TARGET
# ============================================================================
TARGET = "http://localhost:5000"  # CHANGE THIS: Your target server URL
# For testing purposes, you can use:
# - Local development: http://localhost:5000
# - Test server: https://your-test-server.com
# - API endpoint: https://api.yourservice.com/v1

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def print_banner():
    """
    Display program banner with target information and testing purpose.
    
    This function prints a formatted banner showing the target details,
    testing objectives, and a separator for clear output visualization.
    """
    print("⏱️  ADVANCED RATE LIMIT BYPASS TESTER")
    print("=" * 80)
    print(f"🎯 TARGET: {TARGET}")
    print("⚠️  Testing rate limit weaknesses with 15+ techniques")
    print("=" * 80)


def generate_unique_email():
    """
    Generate a unique test email address with timestamp and random suffix.
    
    Returns:
        str: Unique email string in format: test_[timestamp]_[random]@test.com
    """
    timestamp = int(time.time() * 1000)  # Current time in milliseconds
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"test_{timestamp}_{random_str}@test.com"


# ============================================================================
# RATE LIMIT TESTING FUNCTIONS
# ============================================================================

def test_baseline_rate_limit_detection():
    """
    Test 1: Baseline rate limit detection.
    
    Sends rapid requests to various endpoints to identify where rate limits
    are implemented and at what threshold they trigger.
    
    Returns:
        list: Test results showing which endpoints have rate limits and their thresholds
    """
    print("\n1️⃣  [Baseline] Detecting rate limits")
    print("   Finding where rate limits are implemented")
    
    endpoints_to_test = [
        "/api/v1/auth/register",      # Registration endpoint
        "/api/v1/auth/login",         # Login endpoint  
        "/api/v1/auth/forgot-password", # Password reset endpoint
        "/api/v1/events",             # Events API endpoint
        "/api/v1/comments"            # Comments API endpoint
    ]
    
    results = []
    
    for endpoint in endpoints_to_test:
        print(f"\n   Testing {endpoint}:")
        blocked_at = None  # Track when rate limit triggers
        
        # Send 15 rapid requests to trigger rate limit
        for i in range(15):
            try:
                # Test different endpoints with appropriate data
                if "auth/register" in endpoint:
                    email = generate_unique_email()
                    data = {"email": email, "password": "Test123!", "name": "Rate Test"}
                    resp = requests.post(f"{TARGET}{endpoint}", json=data, timeout=2)
                elif "auth/login" in endpoint:
                    # Use wrong credentials to avoid successful login
                    resp = requests.post(f"{TARGET}{endpoint}", 
                                       json={"email": "test@test.com", "password": "wrong"},
                                       timeout=2)
                else:
                    # For other endpoints, send GET request
                    resp = requests.get(f"{TARGET}{endpoint}", timeout=2)
                
                # Check response status
                if resp.status_code == 429:  # 429 = Too Many Requests
                    if not blocked_at:
                        blocked_at = i + 1  # Record first block
                    print(f"     Request {i+1}: 🚫 RATE LIMITED (429)")
                elif resp.status_code >= 400:
                    print(f"     Request {i+1}: {resp.status_code} error")
                else:
                    print(f"     Request {i+1}: {resp.status_code} OK")
                
                time.sleep(0.1)  # Small delay between requests
                
            except requests.exceptions.RequestException:
                print(f"     Request {i+1}: ❌ Connection error")
        
        # Record findings for this endpoint
        if blocked_at:
            print(f"   🔍 Rate limit triggered at request #{blocked_at}")
            results.append(("Rate Limit Baseline", endpoint, f"Blocked at {blocked_at}"))
        else:
            print("   ⚠️  No rate limit detected in 15 requests")
    
    return results


def test_ip_rotation_bypass():
    """
    Test 2: IP rotation simulation for bypassing rate limits.
    
    Simulates using different IP addresses (proxy/VPN rotation) to bypass
    IP-based rate limiting by spoofing X-Forwarded-For and similar headers.
    
    Returns:
        list: Test results showing success rate with IP rotation
    """
    print("\n2️⃣  [IP Rotation] Simulating proxy/VPN rotation")
    print("   Testing if rate limits can be bypassed by changing IP addresses")
    
    # Generate fake IP addresses to simulate different clients
    fake_ips = [
        "192.168.1." + str(i) for i in range(1, 21)  # 20 local IPs
    ] + [
        "10.0.0." + str(i) for i in range(1, 11)     # 10 more local IPs
    ]
    
    success_count = 0
    results = []
    
    # Test first 20 IP addresses
    for i, fake_ip in enumerate(fake_ips[:20]):
        # Set headers to spoof different IP addresses
        headers = {
            "X-Forwarded-For": fake_ip,      # Common proxy header
            "X-Real-IP": fake_ip,            # Alternative proxy header
            "X-Client-IP": fake_ip,          # Client IP header
            "CF-Connecting-IP": fake_ip      # Cloudflare header
        }
        
        try:
            # Try to register with spoofed IP
            resp = requests.post(
                f"{TARGET}/api/v1/auth/register",
                headers=headers,
                json={
                    "email": generate_unique_email(),
                    "password": "Test123!",
                    "name": f"IP Rotation {i}"
                },
                timeout=3
            )
            
            # Count successful requests (not rate limited)
            if resp.status_code != 429:
                success_count += 1
            
            # Show progress every 5 requests
            if i % 5 == 0:
                print(f"     IP {fake_ip}: Status {resp.status_code}")
                
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    print(f"   ✅ {success_count}/20 requests successful with IP rotation")
    if success_count > 15:
        results.append(("IP Rotation", "X-Forwarded-For", f"{success_count}/20 bypassed"))
    
    return results


def test_slowloris_attack():
    """
    Test 3: Slowloris-style slow rate attack.
    
    Tests if slow request intervals bypass rate limits by sending requests
    with random delays between 2-10 seconds to avoid hitting rate limit windows.
    
    Returns:
        list: Test results showing success rate with slow attacks
    """
    print("\n3️⃣  [Slow Attack] Testing slow request intervals")
    print("   Testing if slow requests bypass rate limits (Slowloris attack)")
    
    slow_success = 0
    results = []
    
    # Send 10 requests with random delays between 2-10 seconds
    for i in range(10):
        delay = random.uniform(2, 10)  # Random delay
        time.sleep(delay)  # Wait before sending request
        
        try:
            # Try to login with wrong credentials
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                json={
                    "email": f"slowtest{i}@test.com",
                    "password": "WrongPassword123!"
                },
                timeout=5
            )
            
            # Count successful requests (not rate limited)
            if resp.status_code != 429:
                slow_success += 1
            
            print(f"     Request {i+1} after {delay:.1f}s: {resp.status_code}")
            
        except requests.exceptions.RequestException:
            print(f"     Request {i+1}: Connection error")
    
    print(f"   📊 Slow attack success: {slow_success}/10")
    if slow_success >= 8:
        results.append(("Slow Attack", "2-10s intervals", f"{slow_success}/10 bypassed"))
    
    return results


def test_concurrent_flood_attack():
    """
    Test 4: Concurrent request flooding attack.
    
    Tests if concurrent requests overwhelm rate limits by sending multiple
    requests simultaneously using ThreadPoolExecutor.
    
    Returns:
        list: Test results showing success rate with concurrent flooding
    """
    print("\n4️⃣  [Concurrent Flood] Testing with parallel requests")
    print("   Testing if concurrent requests overwhelm rate limits")
    
    def make_concurrent_request(req_num):
        """
        Helper function to make a registration request for concurrent execution.
        
        Args:
            req_num (int): Request number for identification
            
        Returns:
            int: HTTP status code of the response
        """
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/register",
                json={
                    "email": f"concurrent{req_num}_{int(time.time())}@test.com",
                    "password": "Test123!",
                    "name": f"Concurrent {req_num}"
                },
                timeout=5
            )
            return resp.status_code
        except:
            return 0  # Return 0 for failed requests
    
    print("   Launching 15 concurrent requests...")
    start_time = time.time()  # Start timer
    
    results = []
    
    # Use ThreadPoolExecutor to send 15 concurrent requests
    with ThreadPoolExecutor(max_workers=15) as executor:
        # Submit 15 requests
        futures = [executor.submit(make_concurrent_request, i) for i in range(15)]
        # Wait for all requests to complete and get results
        status_codes = [f.result() for f in as_completed(futures)]
    
    elapsed = time.time() - start_time  # Calculate elapsed time
    
    # Count results
    successful = len([s for s in status_codes if s == 201 or s == 200])  # 201 Created, 200 OK
    rate_limited = len([s for s in status_codes if s == 429])  # 429 Rate Limited
    
    print(f"   ⚡ 15 requests in {elapsed:.2f}s")
    print(f"   ✅ {successful} successful, 🚫 {rate_limited} rate limited")
    
    if successful > 10:
        results.append(("Concurrent Flood", "15 parallel", f"{successful}/15 bypassed"))
    
    return results


def test_user_agent_rotation():
    """
    Test 5: User-Agent rotation testing.
    
    Tests if rate limits treat different User-Agents separately by rotating
    through various browser, mobile, and bot User-Agent strings.
    
    Returns:
        list: Test results showing success rate with User-Agent rotation
    """
    print("\n5️⃣  [User-Agent Rotation] Testing different browsers/devices")
    print("   Testing if rate limits treat different User-Agents separately")
    
    user_agents = [
        # Chrome browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        # Firefox browsers
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
        # Safari browsers
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        # Mobile browsers
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.210 Mobile Safari/537.36",
        # Bots (might be treated differently)
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "curl/7.88.1",  # Command line tool
        ""  # No User-Agent
    ]
    
    ua_success = 0
    results = []
    
    # Test first 8 user agents
    for i, ua in enumerate(user_agents[:8]):
        headers = {"User-Agent": ua} if ua else {}  # Set User-Agent header
        
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                headers=headers,
                json={"email": "test@test.com", "password": "wrong"},
                timeout=3
            )
            
            # Count successful requests (not rate limited)
            if resp.status_code != 429:
                ua_success += 1
            
            # Show user agent name (truncated) and status
            agent_name = ua.split('/')[0][:30] if ua else "No User-Agent"
            print(f"     {agent_name}...: Status {resp.status_code}")
            
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    print(f"   📊 User-Agent rotation: {ua_success}/8 successful")
    
    if ua_success > 5:
        results.append(("User-Agent Rotation", "Multiple UAs", f"{ua_success}/8 bypassed"))
    
    return results


def test_path_variation():
    """
    Test 6: Path variation attacks.
    
    Tests if rate limits are path-specific by trying different URL patterns
    including trailing slashes, query parameters, fragments, and encoding variations.
    
    Returns:
        list: Test results showing accessible path variations
    """
    print("\n6️⃣  [Path Variation] Testing different URL patterns")
    print("   Testing if rate limits are path-specific")
    
    path_variations = [
        "/api/v1/auth/register",       # Normal path
        "/api/v1/auth/register/",      # With trailing slash
        "/api/v1/auth/register?",      # With question mark
        "/api/v1/auth/register?test=1", # With query parameter
        "/api/v1/auth/register#",      # With fragment
        "/api/v1/auth/register/#test", # With fragment value
        "/api//v1//auth//register",    # Double slashes
        "/api/v1/auth/register..",     # Directory traversal attempt
        "/api/v1/auth/register%20",    # Encoded space
        "/API/V1/AUTH/REGISTER",       # Uppercase
        "/api/v1/auth/register.json",  # With extension
        "/api/v1/auth/register.php",   # Different extension
        "/api/v1/auth/register.asp"    # Another extension
    ]
    
    results = []
    
    for path in path_variations:
        try:
            resp = requests.post(
                f"{TARGET}{path}",
                json={"email": generate_unique_email(), "password": "Test123!", "name": "Path Test"},
                timeout=2
            )
            
            # If path is accessible (not 404), check if rate limited
            if resp.status_code != 404:
                print(f"     {path}: Status {resp.status_code}")
                if resp.status_code != 429:
                    results.append(("Path Variation", path, f"Status {resp.status_code}"))
                    
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    return results


def test_parameter_case_variation():
    """
    Test 7: Case variation in JSON parameters.
    
    Tests if JSON parameter case sensitivity affects rate limiting by
    sending parameters with different capitalization patterns.
    
    Returns:
        list: Test results showing which parameter cases are accepted
    """
    print("\n7️⃣  [Parameter Variation] Testing case variations")
    print("   Testing if JSON parameter case affects rate limiting")
    
    param_variations = [
        {"email": "test@test.com", "password": "test", "name": "Test"},  # Lowercase
        {"Email": "test@test.com", "Password": "test", "Name": "Test"},  # Capitalized
        {"EMAIL": "test@test.com", "PASSWORD": "test", "NAME": "Test"},  # Uppercase
        {"eMaIl": "test@test.com", "pAsSwOrD": "test", "nAmE": "Test"},  # Mixed case
        {"e-mail": "test@test.com", "pass-word": "test", "user-name": "Test"}  # With hyphens
    ]
    
    results = []
    
    for params in param_variations:
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/register",
                json=params,
                timeout=2
            )
            
            # If request succeeds with different parameter names, note it
            if resp.status_code < 400:
                first_key = list(params.keys())[0]
                print(f"     {first_key} variation: Status {resp.status_code}")
                results.append(("Parameter Case", first_key, f"Status {resp.status_code}"))
                
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    return results


def test_http_method_variation():
    """
    Test 8: HTTP method variation testing.
    
    Tests if rate limits are method-specific by trying different HTTP methods
    (PUT, PATCH, DELETE) on endpoints that normally use POST.
    
    Returns:
        list: Test results showing which HTTP methods bypass rate limits
    """
    print("\n8️⃣  [Method Variation] Testing different HTTP methods")
    print("   Testing if rate limits are method-specific")
    
    methods = ["POST", "PUT", "PATCH", "DELETE"]
    results = []
    
    for method in methods:
        try:
            if method == "POST":
                # Normal POST request
                resp = requests.post(
                    f"{TARGET}/api/v1/auth/register",
                    json={"email": generate_unique_email(), "password": "Test123!", "name": "Method Test"}
                )
            else:
                # Other methods (PUT, PATCH, DELETE)
                resp = requests.request(
                    method,
                    f"{TARGET}/api/v1/auth/register",
                    json={"email": generate_unique_email(), "password": "Test123!", "name": "Method Test"}
                )
            
            print(f"     {method}: Status {resp.status_code}")
            
            # If non-POST methods work, it could bypass rate limits
            if resp.status_code < 400 and method != "POST":
                results.append(("Method Variation", method, f"Status {resp.status_code}"))
                
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    return results


def test_content_type_variation():
    """
    Test 9: Content-Type header variation.
    
    Tests if different Content-Type headers affect rate limiting by
    sending data in various formats (JSON, form-data, plain text, multipart).
    
    Returns:
        list: Test results showing which content types are accepted
    """
    print("\n9️⃣  [Content-Type] Testing different content types")
    print("   Testing if Content-Type affects rate limiting")
    
    content_types = [
        ("application/json", '{"email":"test@test.com","password":"test"}'),
        ("application/x-www-form-urlencoded", "email=test%40test.com&password=test"),
        ("text/plain", "email=test@test.com,password=test"),
        ("multipart/form-data", "--boundary\r\nContent-Disposition: form-data; name=\"email\"\r\n\r\ntest@test.com\r\n--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\ntest\r\n--boundary--"),
        ("", "raw data")
    ]
    
    results = []
    
    for content_type, data in content_types:
        headers = {"Content-Type": content_type} if content_type else {}
        
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                headers=headers,
                data=data,
                timeout=3
            )
            
            ct_display = content_type[:20] if content_type else "None"
            print(f"     Content-Type {ct_display}...: Status {resp.status_code}")
            
            if resp.status_code < 400:
                results.append(("Content-Type", ct_display, f"Status {resp.status_code}"))
                
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    return results


def test_host_variation():
    """
    Test 10: Host header and alternative host testing.
    
    Tests if different hostnames or IP addresses bypass rate limits by
    accessing the service through various localhost representations.
    
    Returns:
        list: Test results showing accessible host variations
    """
    print("\n🔟 [Host Variation] Testing different hosts")
    print("   Testing if different hostnames bypass rate limits")
    
    # Extract base URL without protocol and port
    base_url = TARGET.replace("http://", "").replace("https://", "")
    if ":" in base_url:
        base_url = base_url.split(":")[0]
    
    hosts = [
        base_url,                    # Original host
        "localhost",                 # Localhost
        "127.0.0.1",                 # Localhost IP
        "0.0.0.0",                   # All interfaces
        "local.host",                # Alternative domain
    ]
    
    results = []
    
    for host in hosts:
        if host == base_url:
            continue  # Skip already tested
            
        # Construct URL with same protocol and port but different host
        protocol = "https://" if TARGET.startswith("https") else "http://"
        port_part = ""
        if ":" in TARGET.split("://")[-1]:
            port_part = ":" + TARGET.split(":")[-1]
        
        test_url = f"{protocol}{host}{port_part}"
        
        try:
            resp = requests.get(test_url, timeout=2)
            if resp.status_code < 400:
                print(f"     Host {host}: Status {resp.status_code}")
                results.append(("Host Variation", host, f"Status {resp.status_code}"))
        except requests.exceptions.RequestException:
            # Host not responding
            pass
    
    return results


def test_request_size_manipulation():
    """
    Test 11: Request size manipulation testing.
    
    Tests if request size affects rate limiting by sending payloads of
    varying sizes from tiny to extremely large.
    
    Returns:
        list: Test results showing how different payload sizes are handled
    """
    print("\n1️⃣1️⃣  [Request Size] Testing with different payload sizes")
    print("   Testing if request size affects rate limiting")
    
    size_tests = [
        ("Tiny", {"email": "a@b.c", "password": "1"}),
        ("Small", {"email": "test@test.com", "password": "normalpassword123"}),
        ("Large", {
            "email": generate_unique_email(),
            "password": "A" * 1000,
            "name": "X" * 1000,
            "extra": {"data": "X" * 5000}
        }),
        ("Huge", {"email": generate_unique_email(), "password": "A" * 10000})
    ]
    
    results = []
    
    for size_name, payload in size_tests:
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/register",
                json=payload,
                timeout=5  # Longer timeout for large payloads
            )
            
            print(f"     {size_name} payload: Status {resp.status_code}")
            results.append(("Request Size", size_name, f"Status {resp.status_code}"))
            
        except Exception as e:
            error_msg = str(e)[:50]
            print(f"     {size_name} payload: Error - {error_msg}")
            results.append(("Request Size", size_name, f"Error: {error_msg}"))
    
    return results


def test_time_window_exploitation():
    """
    Test 12: Time window exploitation testing.
    
    Tests how quickly rate limits reset by triggering a rate limit,
    then waiting various intervals and testing if requests are accepted again.
    
    Returns:
        list: Test results showing rate limit reset times
    """
    print("\n1️⃣2️⃣  [Time Window] Testing rate limit reset")
    print("   Testing how quickly rate limits reset")
    
    results = []
    
    # First, trigger rate limit
    print("   Step 1: Triggering rate limit...")
    for i in range(10):
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                json={"email": "test@test.com", "password": "wrong"},
                timeout=2
            )
            if resp.status_code == 429:  # Found rate limit
                print(f"     Rate limited at request {i+1}")
                break
        except requests.exceptions.RequestException:
            pass
    
    # Wait different amounts of time and test if rate limit resets
    wait_times = [1, 2, 5, 10, 30]  # Seconds to wait
    
    for wait in wait_times:
        print(f"   Step 2: Waiting {wait} seconds...")
        time.sleep(wait)  # Wait specified time
        
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                json={"email": "test@test.com", "password": "wrong"},
                timeout=2
            )
            
            print(f"     After {wait}s: Status {resp.status_code}")
            
            # If not rate limited after waiting, rate limit has reset
            if resp.status_code != 429:
                print(f"     ✅ Rate limit reset after {wait} seconds")
                results.append(("Time Window", f"{wait}s reset", "VULNERABLE"))
                break  # Stop testing once we find reset time
                
        except requests.exceptions.RequestException:
            pass
    
    return results


def test_referer_header_manipulation():
    """
    Test 13: Referer header manipulation.
    
    Tests if different Referer headers affect rate limiting by
    simulating requests from various origins and internal pages.
    
    Returns:
        list: Test results showing Referer header impact
    """
    print("\n1️⃣3️⃣  [Referer Manipulation] Testing Referer header variations")
    print("   Testing if Referer header affects rate limiting")
    
    referers = [
        "",  # No referer
        "https://google.com",  # External site
        "https://facebook.com",  # Another external site
        f"{TARGET}/login",  # Internal page
        f"{TARGET}/",  # Home page
        "https://evil.com",  # Malicious site
    ]
    
    results = []
    
    for referer in referers:
        headers = {"Referer": referer} if referer else {}
        
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                headers=headers,
                json={"email": "test@test.com", "password": "wrong"},
                timeout=3
            )
            
            ref_display = referer[:30] if referer else "None"
            print(f"     Referer {ref_display}...: Status {resp.status_code}")
            
            if resp.status_code != 429:
                results.append(("Referer Header", ref_display, f"Status {resp.status_code}"))
                
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    return results


def test_cookie_manipulation():
    """
    Test 14: Cookie manipulation testing.
    
    Tests if different cookies or session IDs affect rate limiting by
    rotating cookies with various values and formats.
    
    Returns:
        list: Test results showing cookie manipulation impact
    """
    print("\n1️⃣4️⃣  [Cookie Manipulation] Testing cookie variations")
    print("   Testing if cookies affect rate limiting")
    
    cookies_list = [
        {},  # No cookies
        {"session": "1234567890"},  # Simple session ID
        {"session": "".join(random.choices(string.ascii_letters + string.digits, k=32))},  # Random 32-char
        {"session_id": "test123"},  # Different key name
        {"session": "123", "csrf_token": "abc"},  # Multiple cookies
        {"SESSION": "UPPERCASE"},  # Uppercase cookie
        {"sEssIoN": "MiXeDcAsE"}  # Mixed case cookie
    ]
    
    results = []
    
    for cookies in cookies_list:
        try:
            resp = requests.post(
                f"{TARGET}/api/v1/auth/login",
                cookies=cookies,
                json={"email": "test@test.com", "password": "wrong"},
                timeout=3
            )
            
            cookie_display = ", ".join(cookies.keys()) if cookies else "None"
            print(f"     Cookies {cookie_display}: Status {resp.status_code}")
            
            if resp.status_code != 429:
                results.append(("Cookie Manipulation", cookie_display, f"Status {resp.status_code}"))
                
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    return results


def test_api_version_manipulation():
    """
    Test 15: API version manipulation testing.
    
    Tests if different API versions have separate rate limits by trying
    various version patterns in the URL path.
    
    Returns:
        list: Test results showing which API versions are accessible
    """
    print("\n1️⃣5️⃣  [API Version] Testing API version variations")
    print("   Testing if different API versions have separate rate limits")
    
    version_variations = [
        "/api/v1/auth/register",      # v1
        "/api/v2/auth/register",      # v2
        "/api/v3/auth/register",      # v3
        "/api/v1.0/auth/register",    # v1.0
        "/api/v1.1/auth/register",    # v1.1
        "/api/v1.2/auth/register",    # v1.2
        "/api/1/auth/register",       # No 'v' prefix
        "/api/version/1/auth/register", # 'version' prefix
        "/api/v1/auth/register/",      # With trailing slash
        "/api/v1/register",            # Shorter path
    ]
    
    results = []
    
    for version_path in version_variations:
        try:
            resp = requests.post(
                f"{TARGET}{version_path}",
                json={"email": generate_unique_email(), "password": "Test123!", "name": "Version Test"},
                timeout=2
            )
            
            # If path is accessible (not 404), check if rate limited
            if resp.status_code != 404:
                print(f"     {version_path}: Status {resp.status_code}")
                if resp.status_code != 429:
                    results.append(("API Version", version_path, f"Status {resp.status_code}"))
                    
        except requests.exceptions.RequestException:
            # Skip if request fails
            pass
    
    return results


def generate_final_report(all_results):
    """
    Generate a comprehensive final report of all test findings.
    
    Args:
        all_results (list): List of all test results from all techniques
        
    Returns:
        None: Prints formatted report to console
    """
    print("\n" + "=" * 80)
    print("📊 COMPREHENSIVE RATE LIMIT BYPASS REPORT")
    print("=" * 80)
    
    if all_results:
        print(f"Found {len(all_results)} rate limit bypass findings:")
        
        # Group results by category
        categories = {}
        for category, technique, result in all_results:
            if category not in categories:
                categories[category] = []
            categories[category].append((technique, result))
        
        # Show findings for each category
        for category, techniques in categories.items():
            print(f"\n🔸 {category} ({len(techniques)} findings):")
            for technique, result in techniques[:5]:  # Show top 5 per category
                print(f"   • {technique} → {result}")
    else:
        print("✅ Rate limits appear strong - no bypasses found")
    
    # Provide security recommendations
    print("\n💡 SECURITY RECOMMENDATIONS:")
    print("   1. Implement multi-factor rate limiting (IP + User + Session + Behavior)")
    print("   2. Use exponential backoff for suspicious patterns")
    print("   3. Implement request fingerprinting (User-Agent, headers, behavior)")
    print("   4. Add WAF or cloud-based rate limiting (Cloudflare, AWS WAF)")
    print("   5. Implement CAPTCHA after multiple authentication failures")
    print("   6. Monitor for IP rotation patterns and block VPN/proxy ranges")
    print("   7. Use token bucket or leaky bucket algorithm for smooth rate limiting")
    print("   8. Consider implementing device fingerprinting")
    print("   9. Rate limit based on request complexity/size")
    print("   10. Implement global rate limits across all endpoints")


# ============================================================================
# MAIN FUNCTION
# ============================================================================

def main():
    """
    Main function that orchestrates all rate limit bypass tests.
    
    This function:
    1. Displays the banner
    2. Executes all 15 rate limit bypass tests
    3. Collects all results
    4. Generates a comprehensive final report
    
    Returns:
        None: Prints all results to console
    """
    print_banner()  # Display program banner
    
    # Confirm with user before starting tests
    print(f"\n⚠️  This script will send multiple requests to: {TARGET}")
    response = input("Do you have permission to test this target? (yes/no): ")
    
    if response.lower() not in ['yes', 'y']:
        print("Exiting. Please only test systems you have permission to assess.")
        return
    
    all_results = []  # Store all test results
    
    print("\n🚀 Starting comprehensive rate limit bypass testing...")
    
    # Test 1: Baseline detection
    all_results.extend(test_baseline_rate_limit_detection())
    
    # Test 2: IP rotation
    all_results.extend(test_ip_rotation_bypass())
    
    # Test 3: Slowloris attack
    all_results.extend(test_slowloris_attack())
    
    # Test 4: Concurrent flood
    all_results.extend(test_concurrent_flood_attack())
    
    # Test 5: User-Agent rotation
    all_results.extend(test_user_agent_rotation())
    
    # Test 6: Path variation
    all_results.extend(test_path_variation())
    
    # Test 7: Parameter case variation
    all_results.extend(test_parameter_case_variation())
    
    # Test 8: HTTP method variation
    all_results.extend(test_http_method_variation())
    
    # Test 9: Content-Type variation
    all_results.extend(test_content_type_variation())
    
    # Test 10: Host variation
    all_results.extend(test_host_variation())
    
    # Test 11: Request size manipulation
    all_results.extend(test_request_size_manipulation())
    
    # Test 12: Time window exploitation
    all_results.extend(test_time_window_exploitation())
    
    # Test 13: Referer header manipulation
    all_results.extend(test_referer_header_manipulation())
    
    # Test 14: Cookie manipulation
    all_results.extend(test_cookie_manipulation())
    
    # Test 15: API version manipulation
    all_results.extend(test_api_version_manipulation())
    
    # Generate final report
    generate_final_report(all_results)
    
    print("\n✅ Rate limit testing complete! 15 techniques tested.")


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    """
    Entry point for the script execution.
    
    When executed directly, this runs the main() function which
    performs comprehensive rate limit bypass testing.
    """
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user.")
    except Exception as e:
        print(f"\n\n❌ Error occurred: {e}")
        print("Please ensure the target server is running and accessible.")
