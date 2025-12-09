#!/usr/bin/env python3
"""
Web Audit Tool - Cross-platform (Windows/Linux/Mac)
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
import os
from urllib.parse import urljoin, urlparse
import warnings

# Suppress SSL warnings for spider
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# Check and install beautifulsoup4 if needed
try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[*] beautifulsoup4 not found. Installing...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "beautifulsoup4"])
        from bs4 import BeautifulSoup
        print("[+] beautifulsoup4 installed successfully!")
    except Exception as e:
        print(f"[!] Failed to install beautifulsoup4: {e}")
        sys.exit(1)


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
            "nmap": ["sudo", "apt-get", "install", "-y", "nmap"],
            "nikto": ["sudo", "apt-get", "install", "-y", "nikto"],
            "whatweb": ["sudo", "apt-get", "install", "-y", "whatweb"],
            "wafw00f": [sys.executable, "-m", "pip", "install", "wafw00f"],
        },
        "darwin": {
            "nmap": ["brew", "install", "nmap"],
            "nikto": ["brew", "install", "nikto"],
            "whatweb": ["brew", "install", "whatweb"],
            "wafw00f": [sys.executable, "-m", "pip", "install", "wafw00f"],
        },
        "windows": {
            "nmap": None,  # Binary installation required
            "nikto": None,  # Binary installation required
            "whatweb": None,  # Binary installation required
            "wafw00f": [sys.executable, "-m", "pip", "install", "wafw00f"],
        }
    }
    
    os_type = "linux" if is_linux() else "darwin" if is_mac() else "windows" if is_windows() else "unknown"
    return install_commands.get(os_type, {}).get(tool_name, None)

def install_tool_automatically(tool_name):
    """Attempt to install a tool automatically"""
    install_cmd = get_install_command(tool_name)
    
    if install_cmd is None:
        if is_windows():
            return install_windows_tool(tool_name)
        return False
    
    try:
        print(f"[*] Installing {tool_name}...")
        
        # For Linux commands requiring sudo, we need special handling
        if is_linux() and "sudo" in install_cmd:
            print(f"   Running: {' '.join(install_cmd)}")
            result = subprocess.run(install_cmd, capture_output=True, text=True)
        else:
            result = subprocess.run(install_cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] {tool_name} installed successfully!")
            return True
        else:
            print(f"[!] Installation failed for {tool_name}")
            if result.stderr:
                print(f"   Error: {result.stderr[:200]}")
            return False
            
    except Exception as e:
        print(f"[!] Failed to install {tool_name}: {e}")
        return False

def install_windows_tool(tool_name):
    """Install tools on Windows using various methods"""
    print(f"[*] Installing {tool_name} on Windows...")
    
    try:
        if tool_name == "nmap":
            # Try to install nmap via Chocolatey if available
            if shutil.which("choco"):
                print("   Using Chocolatey to install nmap...")
                result = subprocess.run(["choco", "install", "nmap", "-y"], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print("[+] nmap installed successfully via Chocolatey!")
                    return True
            
            # Try winget
            if shutil.which("winget"):
                print("   Using winget to install nmap...")
                result = subprocess.run(["winget", "install", "--id=Insecure.Nmap", "-e", "--silent"], 
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    print("[+] nmap installed successfully via winget!")
                    print("[!] Please restart your terminal or add nmap to PATH")
                    return True
            
            print("[!] Automatic installation failed. Chocolatey or winget not found.")
            print("   Please install manually from: https://nmap.org/download.html")
            return False
            
        elif tool_name == "nikto":
            # Nikto can be installed via Git
            if shutil.which("git"):
                install_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\'), 'nikto')
                if not os.path.exists(install_dir):
                    print(f"   Cloning Nikto to {install_dir}...")
                    result = subprocess.run(["git", "clone", 
                                           "https://github.com/sullo/nikto.git", 
                                           install_dir], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"[+] Nikto cloned successfully to {install_dir}")
                        print(f"   To use: perl {install_dir}\\program\\nikto.pl")
                        return True
                else:
                    print(f"[+] Nikto already exists at {install_dir}")
                    return True
            else:
                print("[!] Git not found. Please install Git first.")
                print("   Download from: https://git-scm.com/download/win")
                return False
                
        elif tool_name == "whatweb":
            # WhatWeb can be installed via Git
            if shutil.which("git"):
                install_dir = os.path.join(os.environ.get('USERPROFILE', 'C:\\'), 'WhatWeb')
                if not os.path.exists(install_dir):
                    print(f"   Cloning WhatWeb to {install_dir}...")
                    result = subprocess.run(["git", "clone", 
                                           "https://github.com/urbanadventurer/WhatWeb.git", 
                                           install_dir], 
                                          capture_output=True, text=True)
                    if result.returncode == 0:
                        print(f"[+] WhatWeb cloned successfully to {install_dir}")
                        print(f"   To use: ruby {install_dir}\\whatweb")
                        return True
                else:
                    print(f"[+] WhatWeb already exists at {install_dir}")
                    return True
            else:
                print("[!] Git not found. Please install Git first.")
                print("   Download from: https://git-scm.com/download/win")
                return False
                
    except Exception as e:
        print(f"[!] Failed to install {tool_name}: {e}")
        return False
    
    return False

def get_tool_command(tool_name):
    """Get the correct command to run a tool based on platform"""
    if is_windows():
        # Check if tool is in PATH first
        if check_tool_installed(tool_name):
            return [tool_name]
        
       
        userprofile = os.environ.get('USERPROFILE', 'C:\\')
        
        if tool_name == "nikto":
            nikto_path = os.path.join(userprofile, 'nikto', 'program', 'nikto.pl')
            if os.path.exists(nikto_path):
                return ["perl", nikto_path]
                
        elif tool_name == "whatweb":
            whatweb_path = os.path.join(userprofile, 'WhatWeb', 'whatweb')
            if os.path.exists(whatweb_path):
                return ["ruby", whatweb_path]
    
   
    return [tool_name]

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
    print(f"\n[WARNING] Tool '{tool_name}' is not installed.")
    
    while True:
        response = input(f"   Do you want to install {tool_name} now? (Yes/No): ").strip().lower()
        if response in ['yes', 'y']:
            # Attempt automatic installation
            success = install_tool_automatically(tool_name)
            
            # On Windows, some tools might be installed but not in PATH
            # Trust the installation function's return value
            if success:
                tool_status[tool_name] = True
                # Verify if tool is now in PATH
                if not check_tool_installed(tool_name) and is_windows():
                    print(f"   [NOTE] {tool_name} installed but may need manual execution")
                return True
            else:
                tool_status[tool_name] = False
                return False
                
        elif response in ['no', 'n']:
            print(f"   Skipping {tool_name}...")
            tool_status[tool_name] = False
            return False
        else:
            print("   Please enter 'Yes' or 'No'")

def spider_website(url, max_pages=50):
    """Spider/crawl a website using available tools"""
    print(f"[*] Starting spider crawl...")
    discovered_urls = []
    
    # Ensure URL has a scheme
    if not url.startswith(('http://', 'https://')):
        url = f"https://{url}"
    
    print(f"   Target: {url}")
    
    # Method 1: curl -I (Quick header check)
    if check_tool_installed("curl"):
        print("   [*] Checking site with curl...")
        try:
            result = subprocess.run(
                ["curl", "-I", url],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                print(f"   [+] Site responds successfully")
                discovered_urls.append(url)
                # Show some header info
                lines = result.stdout.split('\n')[:3]
                for line in lines:
                    if line.strip():
                        print(f"      {line.strip()}")
            else:
                print(f"   [!] Site may not be accessible")
        except Exception as e:
            print(f"   [!] curl check failed: {str(e)[:50]}")
    
    # Method 2: wget --spider (Simple check)
    if check_tool_installed("wget"):
        print("   [*] Running wget spider check...")
        try:
            result = subprocess.run(
                ["wget", "--spider", url],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                print(f"   [+] wget confirmed site is accessible")
            else:
                print(f"   [!] wget spider check failed")
        except Exception as e:
            print(f"   [!] wget error: {str(e)[:50]}")
    
    # Method 3: wget --spider -r (Recursive crawl with log)
    if check_tool_installed("wget"):
        print("   [*] Running wget recursive spider...")
        try:
            log_file = "spider.log"
            # Use exact command: wget --spider -r -nd -nv https://example.com -o spider.log
            result = subprocess.run(
                ["wget", "--spider", "-r", "-nd", "-nv", url, "-o", log_file],
                capture_output=True,
                text=True,
                timeout=20
            )
            
            # Parse the log file to extract URLs
            if os.path.exists(log_file):
                print(f"   [*] Parsing spider log...")
                with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    # Extract all URLs from log
                    import re
                    urls_found = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', content)
                    discovered_urls.extend(urls_found)
                
                os.remove(log_file)  # Clean up
                
                if len(discovered_urls) > 1:  # More than just the base URL
                    discovered_urls = list(set(discovered_urls))  # Remove duplicates
                    print(f"   [+] Found {len(discovered_urls)} unique URLs")
                    return discovered_urls[:max_pages]
        except subprocess.TimeoutExpired:
            print(f"   [!] wget recursive spider timed out")
            if os.path.exists("spider.log"):
                os.remove("spider.log")
        except Exception as e:
            print(f"   [!] wget recursive error: {str(e)[:50]}")
            if os.path.exists("spider.log"):
                os.remove("spider.log")
    
    # Method 4: Python-based spider (Fallback)
    if len(discovered_urls) <= 1:
        print("   [*] Using Python-based spider...")
        try:
            visited = set()
            to_visit = [url]
            base_domain = urlparse(url).netloc
            
            while to_visit and len(visited) < min(max_pages, 15):
                current_url = to_visit.pop(0)
                
                if current_url in visited:
                    continue
                    
                try:
                    response = requests.get(current_url, timeout=5, headers={
                        'User-Agent': 'Mozilla/5.0 (Web Audit Spider)'
                    }, verify=False)
                    visited.add(current_url)
                    if current_url not in discovered_urls:
                        discovered_urls.append(current_url)
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links_count = 0
                    for link in soup.find_all('a', href=True):
                        absolute_url = urljoin(current_url, link['href'])
                        parsed = urlparse(absolute_url)
                        
                        if parsed.netloc == base_domain and absolute_url not in visited and len(to_visit) < 30:
                            to_visit.append(absolute_url)
                            links_count += 1
                    
                    if links_count > 0:
                        print(f"      |- {current_url[:50]}... ({links_count} links)")
                            
                except Exception as e:
                    continue
            
            if discovered_urls:
                discovered_urls = list(set(discovered_urls))  # Remove duplicates
                print(f"   [+] Found {len(discovered_urls)} URLs via Python spider")
        except Exception as e:
            print(f"   [!] Python spider failed: {str(e)[:50]}")
            if not discovered_urls:
                discovered_urls.append(url)
    
    return discovered_urls if discovered_urls else [url]

# -----------------------------
# Code Start Here
# -----------------------------
print("==========================================")
print("        Web Audit tool by WinLwin Oo")
print("==========================================")

target = input("[>] Enter target website (example: https://example.com): ").strip()

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
        print(f"{h}: {r.headers.get(h, ' Missing')}")
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
    print(f"\n Discovered {len(urls)} URLs:")
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
        cmd = get_tool_command("whatweb")
        cmd.append(target)
        subprocess.run(cmd)
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
        cmd = get_tool_command("nikto")
        cmd.extend(["-h", target])
        subprocess.run(cmd)
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
