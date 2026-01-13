#!/usr/bin/env python3
"""
🔍 vulnscanpro -  Web Vulnerability Scanner
GitHub: https://github.com/saranrocks007/vulnscanpro
"""

import requests
import sys
import argparse
import json
import time
import urllib.parse
from urllib.parse import urljoin, urlparse
import threading
from concurrent.futures import ThreadPoolExecutor
import socket
from datetime import datetime

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class VulnScanPro:
    def __init__(self, target_url, threads=10, timeout=5):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        })
        self.threads = threads
        self.timeout = timeout
        self.findings = []
        self.host = urlparse(target_url).netloc
        
    def print_banner(self):
        banner = f"""
{Colors.BOLD}{Colors.CYAN}
   _____ _           _ _____ _____  _    _ 
  / ____| |         | |  __ \\_   _\\| |  | |
 | |  __| |__   __ _| | |__) | | | | |  | |
 | | |_ | '_ \\ / _` | |  ___/  | | | |  | |
 | |__| | | | | (_| | | |      | | | |__| |
  \\_____|_| |_|\\__,_|_|_|      |_|  \\____/ 
{Colors.END}
{Colors.YELLOW}Web Vulnerability Scanner{Colors.END}
    
         """
        print(banner)
    
      def port_scan(self):
        # CEH-Approved Exploitable Ports (High-Value Targets)
        exploitable_ports = [
            80, 443, 8080, 8443, 8000, 8081, 9000, 3000, 5000,  # Web
            4848, 9990, 7001, 9060, 9080, 9443, 7777,  # Admin
            1433, 1434, 3306, 5432, 1521, 27017,       # Database
            20, 21, 445, 139,                          # File transfer
            3389, 5900, 22, 23,                        # Remote access
            25, 465, 587, 993, 995                     # Email
        ]
        
        print(f"{Colors.CYAN}[*] Scanning {len(exploitable_ports)} exploitable ports on {self.host}...{Colors.END}")
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.host, port))
                if result == 0:
                    open_ports.append(port)
                    service = self.get_service_name(port)
                    print(f"{Colors.GREEN}[+] PORT {port:>5} OPEN | {service}{Colors.END}")
                sock.close()
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(scan_port, exploitable_ports)
        
        if open_ports:
            services = [self.get_service_name(p) for p in open_ports]
            self.findings.append({
                "type": "Exploitable Ports", 
                "ports": open_ports,
                "services": services,
                "severity": "CRITICAL"
            })


    
   def fetch_xss_payloads(self):
    """Live XSS payloads from coffinxp/loxs"""
    try:
        url = "https://raw.githubusercontent.com/coffinxp/loxs/main/payloads/xss.txt"
        print(f"{Colors.CYAN}[*] Downloading XSS payloads from coffinxp/loxs...{Colors.END}")
        resp = self.session.get(url, timeout=10)
        if resp.status_code == 200:
            payloads = [line.strip() for line in resp.text.splitlines() if line.strip()]
            print(f"{Colors.GREEN}[+] {len(payloads)} XSS payloads loaded from coffinxp{Colors.END}")
            return payloads[:25]  # Top 25 for speed
    except:
        print(f"{Colors.YELLOW}[*] Using backup XSS payloads{Colors.END}")
    
    # Backup payloads
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "'><svg onload=alert(1)>",
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "<ScRiPt>alert('XSS')</ScRiPt>",
        "\"><script>alert('XSS')</script>",
        "'><script>alert('XSS')</script>",
        "\x3cscript\x3ealert('XSS')\x3c/script\x3e"
    ]

def test_xss(self, url):
    """XSS detection using coffinxp/loxs payloads"""
    xss_payloads = self.fetch_xss_payloads()
    
    parsed = urlparse(url)
    if not parsed.query:
        return
    
    params = parse_qs(parsed.query)
    print(f"{Colors.CYAN}[*] Testing {len(params)} params with coffinxp XSS payloads...{Colors.END}")
    
    for param in params:
        original_value = params[param][0]
        tested = 0
        
        for payload in xss_payloads:
            tested += 1
            if tested > 10:  # Limit to top 10 per param
                break
                
            test_url = url.replace(f"{param}={original_value}", f"{param}={urllib.parse.quote(payload)}")
            
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                # Check reflection
                if payload in resp.text or any(marker in resp.text.lower() for marker in ['alert(', 'onerror', 'onload', 'onload=']):
                    vuln = {
                        "type": "XSS (coffinxp/loxs)",
                        "url": test_url,
                        "parameter": param,
                        "payload_preview": payload[:40] + "..." if len(payload) > 40 else payload,
                        "source": "https://github.com/coffinxp/loxs",
                        "severity": "HIGH"
                    }
                    self.findings.append(vuln)
                    print(f"{Colors.RED}[!] XSS FOUND → {param} = {payload[:30]}...{Colors.END}")
                    break  # Move to next param
            except:
                continue

    
    def fetch_coffinxp_directories(self):
    """18K+ directories from coffinxp/payloads"""
    try:
        url = "https://raw.githubusercontent.com/coffinxp/payloads/main/onelistforallmicro.txt"
        print(f"{Colors.CYAN}[*] Downloading 18K+ directories from coffinxp/payloads...{Colors.END}")
        resp = self.session.get(url, timeout=15)
        if resp.status_code == 200:
            all_dirs = [line.strip() for line in resp.text.splitlines() if line.strip()]
            # Use top 150 for performance (18K too slow for demo)
            directories = all_dirs[:150]
            print(f"{Colors.GREEN}[+] {len(directories)} coffinxp directories loaded{Colors.END}")
            return directories
    except Exception as e:
        print(f"{Colors.YELLOW}[*] coffinxp fetch failed → using fast backup{Colors.END}")
    
    # High-value backup list (coffinxp-style)
    return [
        "admin", "administrator", "wp-admin", "wp-login.php", "login",
        "dashboard", "panel", "control", "manager", "config",
        "config.php", "wp-config.php", "backup", "backups", ".env",
        "api", "api/v1", "v2", "graphql", "phpmyadmin", "adminer",
        "uploads", "upload", "files", "assets", "static", "db",
        "db.sql", "database", "test", "staging", "dev", "beta"
    ]

def directory_scan(self):
    """Directory discovery with coffinxp 18K payloads"""
    directories = self.fetch_coffinxp_directories()
    print(f"{Colors.CYAN}[*] Scanning {len(directories)} coffinxp directories...{Colors.END}")
    
    def test_directory(directory):
        test_url = urljoin(self.target_url.rstrip('/') + '/', directory)
        try:
            resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
            
            # Success conditions
            if resp.status_code == 200 and len(resp.content) > 200:
                service_type = self.classify_directory(directory, resp.text)
                print(f"{Colors.GREEN}[+] DIRECTORY FOUND: {test_url} | {service_type}{Colors.END}")
                self.findings.append({
                    "type": "Directory Discovery (coffinxp)",
                    "url": test_url,
                    "status_code": resp.status_code,
                    "content_length": len(resp.content),
                    "directory": directory,
                    "service_type": service_type,
                    "source": "https://github.com/coffinxp/payloads",
                    "severity": "MEDIUM"
                })
        except:
            pass
    
    # More threads for large wordlist
    with ThreadPoolExecutor(max_workers=self.threads * 2) as executor:
        executor.map(test_directory, directories)

def classify_directory(self, path, content):
    """Identify valuable directories"""
    path_lower = path.lower()
    content_lower = content.lower()
    
    # Config files (CRITICAL)
    if any(x in path_lower for x in ['config', '.env', 'wp-config']):
        return "**CONFIG LEAK**"
    if 'phpmyadmin' in path_lower or 'adminer' in path_lower:
        return "**DB PANEL**"
    
    # Admin panels
    if any(x in path_lower for x in ['admin', 'dashboard', 'panel', 'login']):
        if 'wordpress' in content_lower or 'wp-' in content_lower:
            return "WordPress Admin"
        return "Admin Panel"
    
    # API endpoints
    if any(x in path_lower for x in ['api', 'graphql', 'rest']):
        return "API Endpoint"
    
    return "Directory"

    def security_headers(self):
        print(f"{Colors.CYAN}[*] Security headers check...{Colors.END}")
        try:
            resp = self.session.get(self.target_url, timeout=self.timeout)
            missing = []
            required = ['X-Frame-Options', 'X-Content-Type-Options', 'Strict-Transport-Security']
            
            for h in required:
                if h not in resp.headers:
                    missing.append(h)
            
            if missing:
                print(f"{Colors.YELLOW}[!] Missing: {', '.join(missing)}{Colors.END}")
                self.findings.append({"type": "Missing Headers", "headers": missing, "severity": "MEDIUM"})
        except:
            pass
    
    def generate_report(self):
        report = {
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
            "scanner": "vulnscanpro",
            "findings": self.findings,
            "total": len(self.findings)
        }
        
        print(f"\n{Colors.BOLD}{Colors.GREEN}SCAN COMPLETE: {len(self.findings)} findings{Colors.END}")
        
        filename = f"scan_report_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"{Colors.GREEN}[+] Report: {filename}{Colors.END}")
        return report
    
    def run(self):
    """Main scanning workflow"""
    self.print_banner()
    print(f"{Colors.BLUE}[+] Target: {self.target_url}{Colors.END}\n")
    
    self.port_scan()
    self.security_headers()
    self.test_xss(self.target_url)           # NEW: coffinxp XSS
    self.directory_scan()                    # NEW: coffinxp 18K dirs
    self.sensitive_files()
    
    return self.generate_report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vulnscanpro Web Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=5)
    args = parser.parse_args()
    
    scanner = VulnScanPro(args.url, args.threads, args.timeout)
    scanner.run()
    
    print(f"\n{Colors.BOLD}{Colors.PURPLE}Built by Saran{Colors.END}")



