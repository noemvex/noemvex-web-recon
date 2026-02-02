#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NOEMVEX-WEB v1.1: Stealth Hunter Edition (Final)
Author: Emre 'noemvex' Sahin
License: MIT
Description: Advanced Web Reconnaissance engine. Features:
1. Hybrid Subdomain Discovery (Passive + Active Fallback)
2. Smart Protocol Fallback (Auto-downgrade HTTPS -> HTTP)
3. WAF Evasion (User-Agent Spoofing)
4. Wildcard DNS Detection & Smart Fuzzing
"""

import argparse
import requests
import sys
import socket
import urllib3
from concurrent.futures import ThreadPoolExecutor

# Disable SSL Warnings for cleaner output (Essential for older targets)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

## --- STANDARD UI CLASS ---
class UI:
    PURPLE = '\033[95m'  
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    GREY = '\033[90m'
    END = '\033[0m'

    @staticmethod
    def banner():
        ascii_art = [
            r"███╗   ██╗ ██████╗ ███████╗███╗   ███╗██╗   ██╗███████╗██╗  ██╗",
            r"████╗  ██║██╔═══██╗██╔════╝████╗ ████║██║   ██║██╔════╝╚██╗██╔╝",
            r"██╔██╗ ██║██║   ██║█████╗  ██╔████╔██║██║   ██║█████╗   ╚███╔╝ ",
            r"██║╚██╗██║██║   ██║██╔══╝  ██║╚██╔╝██║╚██╗ ██╔╝██╔══╝   ██╔██╗ ",
            r"██║ ╚████║╚██████╔╝███████╗██║ ╚═╝ ██║ ╚████╔╝ ███████╗██╗  ██╗",
            r"╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝"
        ]
        
        print(f"{UI.GREEN}{UI.BOLD}")
        for line in ascii_art:
            print(line)
        print(f"               {UI.PURPLE}[ NOEMVEX WEB RECON V1.1 STEALTH HUNTER EDITION ]{UI.END}\n")

# --- DEFAULT CONFIGURATION ---
DEFAULT_FILES = [
    ".env", ".git/HEAD", "config.php", "wp-config.php", ".htaccess", 
    "backup.sql", "admin/", "login.php", "dashboard/", "robots.txt",
    "sitemap.xml", "id_rsa", "users.json", "docker-compose.yml", "web.config"
]

# Fallback list for Active Enumeration
FALLBACK_SUBS = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
    "vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host",
    "support", "dev", "web", "bbs", "ww42", "mx", "email", "cloud", "1", "mail1",
    "2", "forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api",
    "exchange", "app", "gov", "news", "sv", "labs"
]

class WebHunter:
    def __init__(self, target, wordlist=None):
        # Intelligent URL Normalization
        target = target.strip().lower()
        # Default to HTTPS, fallback logic will handle issues
        if not target.startswith("http"):
            self.base_url = f"https://{target}".rstrip('/')
            self.domain = target.split('/')[0]
        else:
            self.base_url = target.rstrip('/')
            self.domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        self.wordlist = wordlist
        self.session = requests.Session()
        
        # --- WAF EVASION HEADERS (STEALTH MODE) ---
        # Mimics a real Windows 10 Chrome User to bypass 403 blocks
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })

    def check_connection(self):
        """Verifies target availability with Smart Protocol Fallback (HTTPS -> HTTP)."""
        try:
            print(f"{UI.GREY}[*] Checking connection to {self.base_url}...{UI.END}")
            # Try HTTPS first (or whatever user provided)
            r = self.session.get(self.base_url, timeout=10, verify=False)
            print(f"{UI.GREEN}[+] Target is UP: {self.base_url} (Status: {r.status_code}){UI.END}")
            return True

        except requests.exceptions.RequestException as e:
            # If HTTPS fails, try downgrading to HTTP automatically
            if self.base_url.startswith("https://"):
                print(f"{UI.YELLOW}[!] HTTPS failed. Attempting Protocol Downgrade (HTTP)...{UI.END}")
                self.base_url = self.base_url.replace("https://", "http://")
                try:
                    r = self.session.get(self.base_url, timeout=10, verify=False)
                    print(f"{UI.GREEN}[+] Target is UP (via HTTP): {self.base_url} (Status: {r.status_code}){UI.END}")
                    return True
                except requests.exceptions.RequestException:
                    pass # Downgrade also failed

            # If both fail, report detailed error
            print(f"{UI.RED}[!] Target is DOWN or unreachable: {self.base_url}\n    Error Details: {e}{UI.END}")
            return False

    def check_wildcard(self):
        """Pre-flight check: Detects Wildcard DNS to prevent False Positives."""
        try:
            random_sub = f"noemvex-wildcard-check-999.{self.domain}"
            socket.gethostbyname(random_sub)
            print(f"{UI.YELLOW}[!] Wildcard DNS detected! Active Brute-force might produce false positives.{UI.END}")
            return True
        except socket.gaierror:
            return False

    def analyze_headers(self):
        """Phase 1: Security Header Analysis"""
        print(f"\n{UI.CYAN}--- [ PHASE 1: HEADER SECURITY ANALYSIS ] ---{UI.END}")
        try:
            r = self.session.get(self.base_url, timeout=10, verify=False)
            headers = r.headers
            
            security_headers = ["X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security", "X-XSS-Protection"]

            for h in security_headers:
                if h in headers:
                    print(f"{UI.GREEN}┃  [OK] Header Found: {h}{UI.END}")
                else:
                    print(f"{UI.YELLOW}┃  [WARN] Missing Header: {h}{UI.END}")

            server = headers.get("Server", "Unknown")
            print(f"{UI.BLUE}┃  [INFO] Web Server Detected: {server}{UI.END}")

        except Exception as e:
            print(f"{UI.RED}[!] Header analysis failed: {e}{UI.END}")

    def dns_brute_force(self):
        """Active Fallback: Tries to resolve common subdomains via DNS."""
        if self.check_wildcard():
            print(f"{UI.RED}[-] Skipping Active Brute-Force to avoid false positive flood.{UI.END}")
            return

        print(f"{UI.YELLOW}[!] Switching to Active DNS Brute-Force (Fallback Mode)...{UI.END}")
        found_subs = []
        
        def check_sub(sub):
            full_domain = f"{sub}.{self.domain}"
            try:
                socket.gethostbyname(full_domain)
                print(f"  {UI.GREEN}-> {full_domain}{UI.END}")
                found_subs.append(full_domain)
            except socket.gaierror:
                pass

        with ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_sub, FALLBACK_SUBS)
        
        if not found_subs:
            print(f"{UI.GREY}   No subdomains found in fallback list.{UI.END}")

    def find_subdomains(self):
        """Phase 2: Hybrid Discovery (Passive API -> Active Fallback)"""
        print(f"\n{UI.CYAN}--- [ PHASE 2: HYBRID SUBDOMAIN DISCOVERY ] ---{UI.END}")
        print(f"{UI.GREY}[*] Querying Certificate Transparency logs (Passive)...{UI.END}")

        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            r = requests.get(url, timeout=10)
            
            if r.status_code == 200:
                try:
                    data = r.json()
                    subdomains = set()
                    for entry in data:
                        name = entry['name_value'].lower()
                        if "\n" in name:
                            for n in name.split("\n"): subdomains.add(n)
                        else:
                            subdomains.add(name)

                    if subdomains:
                        for sub in sorted(subdomains):
                            print(f"  {UI.GREEN}-> {sub}{UI.END}")
                        print(f"{UI.GREEN}[+] Passive Scan: {len(subdomains)} subdomains found.{UI.END}")
                    else:
                        print(f"{UI.YELLOW}[!] API returned no data.{UI.END}")
                        self.dns_brute_force()
                except ValueError:
                     print(f"{UI.YELLOW}[!] API returned invalid JSON.{UI.END}")
                     self.dns_brute_force()
            else:
                print(f"{UI.YELLOW}[!] crt.sh API unavailable. Status: {r.status_code}{UI.END}")
                self.dns_brute_force()

        except Exception as e:
            print(f"{UI.RED}[!] Passive Enumeration Failed: {e}{UI.END}")
            self.dns_brute_force()

    def fuzz_file(self, file_path):
        """Worker for directory/file discovery with Smart Filtering."""
        path = file_path if file_path.startswith('/') else f"/{file_path}"
        url = f"{self.base_url}{path}"
        
        try:
            # allow_redirects=False prevents false positives from 301/302 redirects
            r = self.session.get(url, timeout=5, allow_redirects=False, verify=False)
            
            # Smart Filtering: Show 200 (OK), 403 (Forbidden), 401 (Auth Req)
            if r.status_code == 200:
                size = len(r.content)
                print(f"{UI.RED}[CRITICAL] Found: {url} (200 OK) - Size: {size}b{UI.END}")
            elif r.status_code == 403:
                print(f"{UI.BLUE}[FORBIDDEN] Exists: {url} (403){UI.END}")
            elif r.status_code == 401:
                print(f"{UI.YELLOW}[AUTH REQ] Login Found: {url} (401 Unauthorized){UI.END}")
        except:
            pass

    def run_fuzzer(self):
        """Phase 3: Smart Fuzzing"""
        print(f"\n{UI.CYAN}--- [ PHASE 3: SENSITIVE FILE DISCOVERY ] ---{UI.END}")
        
        target_list = []
        if self.wordlist:
            print(f"{UI.GREY}[*] Loading custom wordlist: {self.wordlist}...{UI.END}")
            try:
                with open(self.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                    target_list = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                print(f"{UI.RED}[!] Wordlist not found! Falling back to default list.{UI.END}")
                target_list = DEFAULT_FILES
        else:
            print(f"{UI.GREY}[*] Using built-in default list ({len(DEFAULT_FILES)} artifacts)...{UI.END}")
            target_list = DEFAULT_FILES

        with ThreadPoolExecutor(max_workers=15) as executor:
            executor.map(self.fuzz_file, target_list)

    def run(self):
        UI.banner()
        if self.check_connection():
            self.analyze_headers()
            self.find_subdomains()
            self.run_fuzzer()
        
        print(f"\n{UI.BOLD}{UI.GREEN}[√] RECONNAISSANCE COMPLETED.{UI.END}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NOEMVEX-WEB: Stealth Hunter Edition v1.1")
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., example.com)')
    parser.add_argument('-w', '--wordlist', help='Custom wordlist path for directory fuzzing')
    args = parser.parse_args()

    try:
        hunter = WebHunter(args.url, args.wordlist)
        hunter.run()
    except KeyboardInterrupt:
        print(f"\n{UI.RED}[!] Interrupted by user. Exiting scan safely...{UI.END}")
        sys.exit(0)
