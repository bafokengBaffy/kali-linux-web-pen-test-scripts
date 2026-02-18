#!/bin/bash
echo "🚀 Starting Security Demos"
echo "=========================="
echo ""
echo "1. CSRF Exploit Demo"
python3 csrf_exploit.py
echo ""
read -p "Press Enter to continue..."
echo ""
echo "2. Rate Limit Bypass Demo"
python3 rate_limit_bypass.py
echo ""
read -p "Press Enter to continue..."
echo ""
echo "3. Security Headers Check"
python3 security_headers.py
echo ""
echo "✅ All demos complete!"
