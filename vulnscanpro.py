#!/usr/bin/env python3
"""
vulnscanpro -  Vulnerability Scanner
Saran
"""

import requests
import sys
import argparse
import json
import time
import urllib.parse
from urllib.parse import urljoin, urlparse, parse_qs
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    END = '\033[0m'

class SaranVulnScanPro:
    def __init__(self, target_url, threads=10, timeout=5):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.threads = threads
        self.timeout = timeout
        self.findings = []
        self.host = urlparse(target_url).netloc

    def print_banner(self):  # ← FIXED: 4 spaces (not 2)
        print(f"""
{Colors.BOLD}{Colors.CYAN}
   _____ _           _ _____ _____  _    _ 
  / ____| |         | |  __ \\_   _\\| |  | |
 | |  __| |__   __ _| | |__) | | | | |  | |
 | | |_ | '_ \\ / _` | |  ___/  | | | |  | |
 | |__| | | | | (_| | | |      | | | |__| |
  \\_____|_| |_|\\__,_|_|_|      |_|  \\____/ 
{Colors.END}
{Colors.YELLOW}Web Vulnerability Scanner{Colors.END}
{Colors.PURPLE}Saran{Colors.END}
        """)

    def get_service_name(self, port):  # ← MISSING METHOD ADDED
        services = {
            80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 3389: "RDP",
            445: "SMB", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL"
        }
        return services.get(port, f"TCP-{port}")

    def port_scan(self):  # ← FIXED indentation
        ports = [80, 443, 8080, 8443, 3389, 445, 22, 21, 3306, 1433, 8000, 3000]
        print(f"{Colors.CYAN}[*] Scanning ports on {self.host}...{Colors.END}")
        open_ports = []

        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.5)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                result = sock.connect_ex((self.host, port))
                if result == 0:
                    open_ports.append(port)
                    service = self.get_service_name(port)
                    print(f"{Colors.GREEN}[+] PORT {port:>5} OPEN | {service}{Colors.END}")
                sock.close()
            except:
                pass

        with ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(scan_port, ports)
        
        if open_ports:  # ← FIXED: Proper indentation
            self.findings.append({
                "type": "Open Ports",
                "ports": open_ports,
                "severity": "HIGH"
            })

    # ... [rest of your methods unchanged] ...

    def run(self):
        self.print_banner()
        print(f"{Colors.BLUE}[*] Target: {self.target_url}{Colors.END}\n")
        self.port_scan()
        self.security_headers()
        self.test_xss(self.target_url)
        self.directory_scan()
        self.sensitive_files()
        return self.generate_report()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="vulnscanpro - Web Scanner")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout")
    args = parser.parse_args()
    
    scanner = SaranVulnScanPro(args.url, args.threads, args.timeout)
    scanner.run()
