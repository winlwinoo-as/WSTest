#!/usr/bin/env python3
import requests
import ssl
import socket
import subprocess
import dns.resolver

def print_header(title):
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

# -----------------------------
# MAIN
# -----------------------------
print("==========================================")
print("        Web Audit tool by WinLwin Oo")
print("==========================================")

target = input("➡️  Enter target website (example: https://example.com): ").strip()

if not target:
    print(" No target entered. Exiting.")
    exit()

# Normalize domain
domain = target.replace("https://", "").replace("http://", "").split("/")[0]

# 1. Basic Headers
print_header("1. Basic HTTP Headers")
try:
    r = requests.get(target, timeout=10)
    for h, v in r.headers.items():
        print(f"{h}: {v}")
except Exception as e:
    print("Error:", e)

# 2. Security Headers
print_header("2. Security Headers")
security_headers = ["Strict-Transport-Security", "X-Frame-Options",
                    "X-XSS-Protection", "Content-Security-Policy",
                    "Referrer-Policy", "Permissions-Policy"]

try:
    r = requests.get(target, timeout=10)
    for h in security_headers:
        print(f"{h}: {r.headers.get(h, '❌ Missing')}")
except:
    print("Cannot fetch security headers.")

# 3. Cookies
print_header("3. Cookies")
try:
    r = requests.get(target, timeout=10)
    if "set-cookie" in r.headers:
        print(r.headers["set-cookie"])
    else:
        print("No cookies found.")
except:
    print("Cannot read cookies.")

# 4. DNS Records
print_header("4. DNS Records")
try:
    for qtype in ["A", "AAAA", "NS", "MX", "TXT"]:
        try:
            answers = dns.resolver.resolve(domain, qtype)
            for rdata in answers:
                print(f"{qtype}: {rdata}")
        except:
            pass
except:
    print("DNS lookup failed.")

# 5. SSL Certificate Info
print_header("5. SSL Certificate Info")
try:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            print(cert)
except Exception as e:
    print("Cannot retrieve SSL certificate:", e)

# 6. WhatWeb (external)
print_header("6. WhatWeb Fingerprinting")
try:
    subprocess.run(["whatweb", target])
except:
    print("WhatWeb not installed.")

# 7. WAFW00F (external)
print_header("7. WAF Detection (wafw00f)")
try:
    subprocess.run(["wafw00f", target])
except:
    print("WAFW00F not installed.")

# 8. Nikto (external)
print_header("8. Nikto Scan")
try:
    subprocess.run(["nikto", "-h", target])
except:
    print("Nikto not installed.")

# 9. Nmap Scan
print_header("9. Nmap Port Scan")
try:
    subprocess.run(["nmap", "-sV", "-Pn", domain])
except:
    print("Nmap not installed.")

# 10. Bot Defense Test
print_header("10. Bot Defense (SQLMAP User-Agent)")
try:
    r = requests.get(target, headers={"User-Agent": "sqlmap"}, timeout=10)
    print(f"Status: {r.status_code}")
    print("Headers:", r.headers)
except:
    print("Bot defense check failed.")

print("\n==========================================")
print(              "Web Audit Completed")
print("==========================================")
