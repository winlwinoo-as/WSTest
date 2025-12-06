#!/bin/bash

echo "=========================================="
echo " 🔍 Web Security Audit Tool by WinLwin Oo"
echo "=========================================="
echo ""
read -p " Enter target website (example: https://example.com): " TARGET
echo ""

if [ -z "$TARGET" ]; then
    echo " No target entered. Exiting."
    exit 1
fi

DOMAIN=$(echo $TARGET | sed -E 's_https?://__' | cut -d/ -f1)

echo "=========================================="
echo "   Starting Scan for: $TARGET"
echo "=========================================="
echo ""

# 1) Basic Headers
echo "=== 1. Basic HTTP Headers ==="
curl -sI "$TARGET"

# 2) Security Headers
echo -e "\n=== 2. Security Headers ==="
curl -sI "$TARGET" | grep -Ei "strict|frame|x-xss|csp|policy|referrer|hsts"

# 3) Cookies
echo -e "\n=== 3. Cookies ==="
curl -sI "$TARGET" | grep -i "set-cookie"

# 4) Technology detection
echo -e "\n=== 4. WhatWeb Fingerprint ==="
whatweb -v "$TARGET"

# 5) WAF Detection
echo -e "\n=== 5. WAF Detection (wafw00f) ==="
wafw00f "$TARGET"

# 6) Nikto Scan
echo -e "\n=== 6. Nikto Vulnerability Scan ==="
nikto -h "$TARGET"

# 7) DNS Records
echo -e "\n=== 7. DNS Records ==="
dig "$DOMAIN" ANY

echo -e "\n=== DNS Trace ==="
dig +trace "$DOMAIN"

# 8) SSL Scan
echo -e "\n=== 8. SSL/TLS Scan ==="
sslscan "$DOMAIN"

# 9) Nmap scan
echo -e "\n=== 9. Nmap Port + Service Scan ==="
nmap -sV -Pn "$DOMAIN"

# 10) Bot defense test
echo -e "\n=== 10. Bot Defense Test (SQLMAP UA) ==="
curl -I "$TARGET" --user-agent "sqlmap"


echo -e "\n=========================================="
echo "   	Web Security Audit Completed"
echo "=========================================="
