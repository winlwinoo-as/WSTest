#!/usr/bin/env python3
"""
Web Audit Tool - Cross-platform (Windows/Linux)
Requirements: 
    pip install requests dnspython beautifulsoup4
Optional tools: nmap, nikto, whatweb, wafw00f
"""
import requests
import ssl
import socket
import subprocess
import dns.resolver
import platform
import shutil
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Tool availability cache
tool_status = {}

def print_header(title):
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

def is_windows():
    """Check if running on Windows"""
    return platform.system().lower() == "windows"

def is_linux():
    """Check if running on Linux"""
    return platform.system().lower() == "linux"

def is_mac():
    """Check if running on macOS"""
    return platform.system().lower() == "darwin"

def check_tool_installed(tool_name):
    """Check if a tool is installed on the system"""
    return shutil.which(tool_name) is not None

def get_install_command(tool_name):
    """Get the installation command based on OS and tool"""
    install_commands = {
        "linux": {
            "nmap": "sudo apt-get install nmap",
            "nikto": "sudo apt-get install nikto",
            "whatweb": "sudo apt-get install whatweb",
            "wafw00f": "pip3 install wafw00f",
        },
        "darwin": {
            "nmap": "brew install nmap",
            "nikto": "brew install nikto",
            "whatweb": "brew install whatweb",
            "wafw00f": "pip3 install wafw00f",
        },
        "windows": {
            "nmap": "Download from https://nmap.org/download.html and install",
            "nikto": "Install via Git: git clone https://github.com/sullo/nikto",
            "whatweb": "Install via Git: git clone https://github.com/urbanadventurer/WhatWeb",
            "wafw00f": "pip install wafw00f",
        }
    }
    
    os_type = "linux" if is_linux() else "darwin" if is_mac() else "windows" if is_windows() else "unknown"
    return install_commands.get(os_type, {}).get(tool_name, f"Please install {tool_name} manually")

def prompt_install_tool(tool_name):
    """Prompt user to install a tool if not found"""
    global tool_status
    

    if tool_name in tool_status:
        return tool_status[tool_name]
    
    # Check if tool is installed
    if check_tool_installed(tool_name):
        tool_status[tool_name] = True
        return True
    
    # Tool not found, ask user
    print(f"\n⚠️  Tool '{tool_name}' is not installed.")
    install_cmd = get_install_command(tool_name)
    print(f"   Installation: {install_cmd}")
    
    while True:
        response = input(f"   Do you want to install {tool_name} now? (Yes/No): ").strip().lower()
        if response in ['yes', 'y']:
            print(f"   Please install {tool_name} manually and run the script again.")
            print(f"   Command: {install_cmd}")
            tool_status[tool_name] = False
            return False
        elif response in ['no', 'n']:
            print(f"   Skipping {tool_name}...")
            tool_status[tool_name] = False
            return False
        else:
            print("   Please enter 'Yes' or 'No'")

def spider_website(url, max_pages=50):
    """Spider/crawl a website to discover URLs"""
    visited = set()
    to_visit = [url]
    discovered_urls = []
    
    base_domain = urlparse(url).netloc
    
    print(f"🕷️  Starting spider crawl (max {max_pages} pages)...")
    
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        
        if current_url in visited:
            continue
            
        try:
            print(f"   Crawling: {current_url}")
            response = requests.get(current_url, timeout=5, headers={
                'User-Agent': 'Mozilla/5.0 (Web Audit Spider)'
            })
            visited.add(current_url)
            discovered_urls.append(current_url)
            
            
            soup = BeautifulSoup(response.text, 'html.parser')
            for link in soup.find_all('a', href=True):
                absolute_url = urljoin(current_url, link['href'])
                parsed = urlparse(absolute_url)
                
               
                if parsed.netloc == base_domain and absolute_url not in visited:
                    to_visit.append(absolute_url)
                    
        except Exception as e:
            print(f"   Error crawling {current_url}: {e}")
            continue
    
    return discovered_urls

# -----------------------------
# Code Start Here
# -----------------------------
print("==========================================")
print("        Web Audit tool by WinLwin Oo")
print("==========================================")

target = input("➡️  Enter target website (example: https://example.com): ").strip()

if not target:
    print(" No target entered. Exiting.")
    exit()


domain = target.replace("https://", "").replace("http://", "").split("/")[0]

# Basic Headers
print_header("1. Basic HTTP Headers")
try:
    r = requests.get(target, timeout=10)
    for h, v in r.headers.items():
        print(f"{h}: {v}")
except Exception as e:
    print("Error:", e)

# Security Headers
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

# Cookies
print_header("3. Cookies")
try:
    r = requests.get(target, timeout=10)
    if "set-cookie" in r.headers:
        print(r.headers["set-cookie"])
    else:
        print("No cookies found.")
except:
    print("Cannot read cookies.")

# DNS Records
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

# SSL Certificate Info
print_header("5. SSL Certificate Info")
try:
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443)) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
            cert = ssock.getpeercert()
            print(cert)
except Exception as e:
    print("Cannot retrieve SSL certificate:", e)

# Spider/Crawler
print_header("6. Spider/Web Crawler")
try:
    urls = spider_website(target, max_pages=20)
    print(f"\n✅ Discovered {len(urls)} URLs:")
    for url in urls[:30]:  # Show first 30 URLs
        print(f"   - {url}")
    if len(urls) > 30:
        print(f"   ... and {len(urls) - 30} more URLs")
except Exception as e:
    print(f"Spider failed: {e}")

# WhatWeb (external)
print_header("7. WhatWeb Fingerprinting")
if prompt_install_tool("whatweb"):
    try:
        subprocess.run(["whatweb", target])
    except Exception as e:
        print(f"WhatWeb execution failed: {e}")
else:
    print("Skipping WhatWeb scan.")

# WAFW00F (external)
print_header("8. WAF Detection (wafw00f)")
if prompt_install_tool("wafw00f"):
    try:
        subprocess.run(["wafw00f", target])
    except Exception as e:
        print(f"WAFW00F execution failed: {e}")
else:
    print("Skipping WAFW00F scan.")

# Nikto (external)
print_header("9. Nikto Scan")
if prompt_install_tool("nikto"):
    try:
        subprocess.run(["nikto", "-h", target])
    except Exception as e:
        print(f"Nikto execution failed: {e}")
else:
    print("Skipping Nikto scan.")

# Nmap Scan
print_header("10. Nmap Port Scan")
if prompt_install_tool("nmap"):
    try:
        subprocess.run(["nmap", "-sV", "-Pn", domain])
    except Exception as e:
        print(f"Nmap execution failed: {e}")
else:
    print("Skipping Nmap scan.")

# Bot Defense Test
print_header("11. Bot Defense (SQLMAP User-Agent)")
try:
    r = requests.get(target, headers={"User-Agent": "sqlmap"}, timeout=10)
    print(f"Status: {r.status_code}")
    print("Headers:", r.headers)
except:
    print("Bot defense check failed.")

print("\n==========================================")
print(              "Web Audit Completed")
print("==========================================")
