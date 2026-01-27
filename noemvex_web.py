#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NOEMVEX-WEB v1.0: Hunter Edition
Author: Emre 'noemvex' Sahin
License: MIT
Description: Lightweight Web Reconnaissance engine. Automates passive subdomain enumeration (crt.sh), security header analysis, and sensitive file discovery.
"""

import argparse
import requests
import sys
from concurrent.futures import ThreadPoolExecutor

# --- STANDARD UI CLASS (Unified Noemvex Design System) ---
class UI:
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
        print(f"{UI.RED}{UI.BOLD}")
        print("  _   _  ____  ______ __  __ __      __ ______  __   __")
        print(" | \ | |/ __ \|  ____|  \/  |\ \    / /|  ____|\ \ / /")
        print(" |  \| | |  | | |__  | \  / | \ \  / / | |__    \ V / ")
        print(" | . ` | |  | |  __| | |\/| |  \ \/ /  |  __|    > <  ")
        print(" | |\  | |__| | |____| |  | |   \  /   | |____  / . \ ")
        print(" |_| \_|\____/|______|_|  |_|    \/    |______|/_/ \_\\")
        print(f"               {UI.YELLOW}[ WEB RECON EDITION v1.0 ]{UI.END}\n")

# --- TARGET CONFIGURATION ---
CRITICAL_FILES = [
    ".env", ".git/HEAD", "config.php", "wp-config.php", ".htaccess", 
    "backup.sql", "admin/", "login.php", "dashboard/", "robots.txt",
    "sitemap.xml", "id_rsa", "users.json", "docker-compose.yml"
]

class WebHunter:
    def __init__(self, target):
        # Senior Fix: Normalize URL and strip trailing slashes to prevent URL doubling
        target = target.strip().lower()
        if not target.startswith("http"):
            self.base_url = f"https://{target}".rstrip('/')
            self.domain = target.split('/')[0]
        else:
            self.base_url = target.rstrip('/')
            self.domain = target.replace("https://", "").replace("http://", "").split("/")[0]

        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Noemvex-WebHunter/1.0'})

    def check_connection(self):
        """Verifies target availability."""
        try:
            r = self.session.get(self.base_url, timeout=10)
            print(f"{UI.GREEN}[+] Target is UP: {self.base_url} (Status: {r.status_code}){UI.END}")
            return True
        except requests.exceptions.RequestException:
            print(f"{UI.RED}[!] Target is DOWN or unreachable: {self.base_url}{UI.END}")
            return False

    def analyze_headers(self):
        """Phase 1: Security Header Analysis"""
        print(f"\n{UI.CYAN}--- [ PHASE 1: HEADER SECURITY ANALYSIS ] ---{UI.END}")
        try:
            r = self.session.get(self.base_url, timeout=10)
            headers = r.headers
            
            security_headers = [
                "X-Frame-Options", 
                "Content-Security-Policy", 
                "Strict-Transport-Security",
                "X-XSS-Protection"
            ]

            for h in security_headers:
                if h in headers:
                    print(f"{UI.GREEN}┃  [OK] Header Found: {h}{UI.END}")
                else:
                    print(f"{UI.YELLOW}┃  [WARN] Missing Header: {h}{UI.END}")

            server = headers.get("Server", "Unknown")
            print(f"{UI.BLUE}┃  [INFO] Web Server Detected: {server}{UI.END}")

        except Exception as e:
            print(f"{UI.RED}[!] Header analysis failed: {e}{UI.END}")

    def find_subdomains(self):
        """Phase 2: Passive Subdomain Enumeration (crt.sh)"""
        print(f"\n{UI.CYAN}--- [ PHASE 2: PASSIVE SUBDOMAIN ENUM (crt.sh) ] ---{UI.END}")
        print(f"{UI.GREY}[*] Querying Certificate Transparency logs...{UI.END}")

        try:
            url = f"https://crt.sh/?q=%25.{self.domain}&output=json"
            # Senior Fix: Added specific timeout for external API call
            r = requests.get(url, timeout=15)
            
            if r.status_code == 200:
                data = r.json()
                subdomains = set()
                for entry in data:
                    # Clean up wildcards and duplicates
                    name = entry['name_value'].lower()
                    if "\n" in name:
                        for n in name.split("\n"):
                            subdomains.add(n)
                    else:
                        subdomains.add(name)

                for sub in sorted(subdomains):
                    print(f"  {UI.GREEN}-> {sub}{UI.END}")
                
                print(f"{UI.GREEN}[+] Total Subdomains Found: {len(subdomains)}{UI.END}")
            else:
                print(f"{UI.YELLOW}[!] crt.sh API unavailable (Status: {r.status_code}).{UI.END}")
        except Exception as e:
            print(f"{UI.RED}[!] Enumeration failed: {e}{UI.END}")

    def fuzz_file(self, file_path):
        """Worker for file discovery."""
        # Ensure path starts with a slash
        path = file_path if file_path.startswith('/') else f"/{file_path}"
        url = f"{self.base_url}{path}"
        try:
            # Senior Fix: allow_redirects=False is crucial to avoid false 200s from login pages
            r = self.session.get(url, timeout=5, allow_redirects=False)
            if r.status_code == 200:
                print(f"{UI.RED}[CRITICAL] Found: {url} (200 OK){UI.END}")
            elif r.status_code in [301, 302]:
                print(f"{UI.YELLOW}[REDIRECT] Found: {url}{UI.END}")
            elif r.status_code == 403:
                print(f"{UI.BLUE}[FORBIDDEN] Exists: {url} (403){UI.END}")
        except:
            pass

    def run_fuzzer(self):
        """Phase 3: Sensitive File Fuzzing"""
        print(f"\n{UI.CYAN}--- [ PHASE 3: SENSITIVE FILE DISCOVERY ] ---{UI.END}")
        print(f"{UI.GREY}[*] Fuzzing for {len(CRITICAL_FILES)} critical artifacts...{UI.END}")

        with ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(self.fuzz_file, CRITICAL_FILES)

    def run(self):
        UI.banner()
        if self.check_connection():
            self.analyze_headers()
            self.find_subdomains()
            self.run_fuzzer()
        
        print(f"\n{UI.BOLD}{UI.GREEN}[√] RECONNAISSANCE COMPLETED.{UI.END}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NOEMVEX-WEB: Hunter Edition")
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., example.com)')
    args = parser.parse_args()

    hunter = WebHunter(args.url)
    hunter.run()