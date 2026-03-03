🛡️ Security Testing Suite

Author: Bafokeng Khoali

Title: Cyber Security Educator | BSc Information Technology


Organization: Baffy’s Computer Solutions

Version: 1.0

Last Updated: February 2026



📌 Overview

The Security Testing Suite is a professional-grade collection of automated security assessment tools designed for authorized penetration testing and vulnerability assessment of web applications and APIs.

This suite focuses on identifying common yet critical security weaknesses including:

Cross-Site Request Forgery (CSRF)

Rate Limiting Bypass Vulnerabilities

Missing or Misconfigured Security Headers

Each tool is designed for practical security auditing, red-team simulations, and defensive validation in controlled or authorized environments.


🛡️ 1. Ultimate CSRF Exploit Tester (40+ Tests)

A comprehensive CSRF vulnerability assessment tool that evaluates over 40 attack vectors and automatically generates proof-of-concept exploit files.

🔎 Key Capabilities

40+ CSRF attack vector tests

GET-based CSRF detection

Origin and Referer header validation bypass testing

Content-Type validation bypass

JSON-based CSRF attacks

CORS misconfiguration testing

Cookie security analysis

CSRF token implementation analysis

Double-submit cookie pattern validation

HTTP method confusion attacks

Flash CSRF via crossdomain.xml

Automatic exploit generation (5 PoC files)

🚀 Usage
# Step 1: Update target URL inside the script
# Modify the TARGET variable at the top of the file

# Step 2: Run the tool
python3 csrf_exploit.py

# Step 3: Review generated exploit files

📂 Generated Files

csrf_results.json

csrf_basic.html

csrf_advanced.html

csrf_clickjacking.html

csrf_json.html

csrf_stealth.html

📊 Output Report

JSON structured results

5 HTML exploit proof-of-concept files

Detailed console findings

Risk classification and mitigation guidance

⏱️ 2. Advanced Rate Limit Bypass Tester (15+ Techniques)

A comprehensive rate-limiting security assessment tool that evaluates over 15 bypass techniques including header manipulation, concurrency abuse, and timing exploitation.

🔎 Key Capabilities

Baseline rate limit detection

IP rotation simulation (X-Forwarded-For, X-Real-IP)

Slow attack simulation (2–10 second intervals)

Concurrent request flooding (ThreadPoolExecutor)

User-Agent rotation (20+ profiles)

Path variation and encoding attacks

Parameter case variation

HTTP method manipulation (PUT, PATCH, DELETE)

Content-Type header tampering

Host header variation

Request size manipulation

Time window exploitation

Referer header manipulation

Cookie tampering

API version manipulation

🚀 Usage
# Step 1: Set target URL in script
# Modify the TARGET variable

# Step 2: Execute
python3 rate_limit_bypass.py

📊 Output Report

Real-time console results

Categorized bypass findings

Identified weaknesses

Security hardening recommendations

🔒 3. Ultimate Security Headers Tester (50+ Checks)

A professional-grade HTTP security header analyzer performing over 50 checks against best practice standards.

🔎 Key Capabilities

50+ security header validations

Content Security Policy (CSP) analysis and scoring

HTTP Strict Transport Security (HSTS) validation

X-Frame-Options analysis

X-Content-Type-Options validation

Referrer-Policy checks

Cookie security flags analysis (Secure, HttpOnly, SameSite)

CORS configuration assessment

Information disclosure detection

TLS version and certificate validation

Cross-Origin Policy testing (COOP, COEP, CORP)

Cache-Control review for sensitive endpoints

🚀 Usage
# Step 1: Update TARGET variable
# Step 2: Run the tool
python3 security_headers.py

📊 Output Report

security_headers_results.json

Security score (0–100%)

Vulnerability severity breakdown

Actionable remediation guidance

📁 Project Structure
security-testing-suite/
├── csrf_exploit.py
├── rate_limit_bypass.py
├── security_headers.py
├── README.md
├── csrf_results.json
├── csrf_basic.html
├── csrf_advanced.html
├── csrf_clickjacking.html
├── csrf_json.html
├── csrf_stealth.html
└── security_headers_results.json

⚙️ Configuration

Each script requires setting a target:

TARGET = "https://your-authorized-target.com"


Only test applications you own or have explicit written authorization to assess.

🛠️ Requirements
pip install requests


All tools are built using Python 3 and the requests library for HTTP communication.

⚖️ Legal & Ethical Notice

⚠️ IMPORTANT

These tools are strictly intended for:

Applications you own

Systems you have written authorization to test

Approved staging or testing environments

Unauthorized security testing may violate:

Computer Fraud and Abuse Act (CFAA)

GDPR and data protection laws

Terms of service agreements

Local and international cybersecurity laws

The author assumes no liability for misuse.

Always obtain written authorization before conducting any form of security testing.

📚 References & Standards

OWASP CSRF Prevention Cheat Sheet

OWASP Denial of Service & Rate Limiting Guidelines

OWASP Secure Headers Project

Mozilla Observatory

👨‍💻 About the Author

Bafokeng Khoali
Cyber Security Educator
BSc Information Technology
Founder – Baffy’s Computer Solutions

Specializing in:

Web Application Security

API Security Testing

Ethical Hacking

Secure Software Development

Backend Security Architecture

📝 License

This project is provided for:

Educational use

Research purposes

Authorized penetration testing

Use responsibly and ethically.
