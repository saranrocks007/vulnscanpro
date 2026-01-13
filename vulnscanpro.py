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
        ports = [21,22,23,25,53,80,110,143,443,993,995,8080,8443]
        print(f"{Colors.CYAN}[*] Scanning ports on {self.host}...{Colors.END}")
        open_ports = []
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if sock.connect_ex((self.host, port)) == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, ports)
        
        if open_ports:
            print(f"{Colors.GREEN}[+] Open ports: {', '.join(map(str, open_ports))}{Colors.END}")
            self.findings.append({"type": "Open Ports", "ports": open_ports, "severity": "INFO"})
    
    def test_xss(self, url):
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'><svg onload=alert(1)>",
            "javascript:alert('XSS')"
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params:
                for payload in xss_payloads:
                    test_url = url.replace(f"{param}={params[param][0]}", f"{param}={urllib.parse.quote(payload)}")
                    try:
                        resp = self.session.get(test_url, timeout=self.timeout)
                        if any(p in resp.text for p in xss_payloads):
                            vuln = {"type": "XSS", "url": test_url, "param": param, "severity": "HIGH"}
                            self.findings.append(vuln)
                            print(f"{Colors.RED}[!] XSS: {test_url[:80]}...{Colors.END}")
                    except:
                        pass
    
    def directory_scan(self):
        dirs = ["admin", "login", "wp-admin", "api", "config", "backup", "test"]
        print(f"{Colors.CYAN}[*] Directory brute force...{Colors.END}")
        
        def test_dir(d):
            url = urljoin(self.target_url, d)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    print(f"{Colors.GREEN}[+] DIR: {url}{Colors.END}")
                    self.findings.append({"type": "Directory", "url": url, "severity": "MEDIUM"})
            except:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test_dir, dirs)
    
    def sensitive_files(self):
        files = ["/robots.txt", "/.env", "/config.php", "/backup.zip"]
        print(f"{Colors.CYAN}[*] Sensitive files check...{Colors.END}")
        
        for f in files:
            url = urljoin(self.target_url, f)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code == 200:
                    print(f"{Colors.RED}[!] SENSITIVE: {url}{Colors.END}")
                    self.findings.append({"type": "Sensitive File", "url": url, "severity": "HIGH"})
            except:
                pass
    
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
            "scanner": "saran-vulnscanpro (CEH #ECC7460938521)",
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
        self.print_banner()
        print(f"{Colors.BLUE}Target: {self.target_url}{Colors.END}\n")
        
        self.port_scan()
        self.security_headers()
        self.directory_scan()
        self.sensitive_files()
        self.test_xss(self.target_url)
        
        return self.generate_report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="saran-vulnscanpro - CEH Web Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10)
    parser.add_argument("--timeout", type=int, default=5)
    args = parser.parse_args()
    
    scanner = VulnScanPro(args.url, args.threads, args.timeout)
    scanner.run()
    
    print(f"\n{Colors.BOLD}{Colors.PURPLE}Built by Saran{Colors.END}")

