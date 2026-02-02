# NOEMVEX-WEB v1.1 [STEALTH HUNTER EDITION]
![Python](https://img.shields.io/badge/Python-3.x-blue) ![License](https://img.shields.io/badge/License-MIT-grey) ![Focus](https://img.shields.io/badge/Focus-Web%20Recon-yellow) ![Type](https://img.shields.io/badge/Edition-Red%20Edition-red)

> **"Ghost in the Machine."**
> Advanced Web Reconnaissance engine featuring WAF Evasion, Hybrid Subdomain Discovery, and Smart Protocol Fallback.
> ⚠️ **Disclaimer:** This tool is for educational purposes only. [Read the full Legal Disclaimer](#️-legal-disclaimer)

---
##  About
**NOEMVEX-WEB** is a resilient reconnaissance tool engineered for modern web engagements. Unlike standard scanners that crash on timeout or get blocked by WAFs, this engine adapts. It automatically downgrades protocols (HTTPS -> HTTP) when needed, bypasses 403 blocks via User-Agent spoofing, and switches to active DNS brute-forcing when passive APIs fail.


##  Key Capabilities
* ** WAF Evasion (Stealth Mode):** Mimics legitimate Windows 10/Chrome traffic patterns to bypass basic WAF/IPS 403 blocks.
* ** Smart Protocol Fallback:** Automatically detects connection failures on HTTPS and downgrades to HTTP to ensure target availability.
* ** Hybrid Subdomain Discovery:** Uses passive Certificate Transparency logs (crt.sh) primarily, but instantly triggers an Active DNS Brute-Force module if APIs timeout.
* ** Smart Noise Filtering:** Filters out redirect noise (301/302), highlighting only actionable **200 (OK)** and **403 (Forbidden)** artifacts.
* ** Wildcard DNS Detection:** Pre-flight check to prevent false-positive floods on wildcard-enabled domains.


---
##  Usage

### 1. Requirements
pip install requests

### 2. Basic Scan (Auto-Stealth)
python3 noemvex_web.py -u example.com

### 3. Advanced Scan (Custom Wordlist)
python3 noemvex_web.py -u example.com -w /usr/share/wordlists/dirb/common.txt

---

##  Output Preview (Real Scenario)

    ███╗   ██╗ ██████╗ ███████╗███╗   ███╗██╗   ██╗███████╗██╗  ██╗
    ████╗  ██║██╔═══██╗██╔════╝████╗ ████║██║   ██║██╔════╝╚██╗██╔╝
    ██╔██╗ ██║██║   ██║█████╗  ██╔████╔██║██║   ██║█████╗   ╚███╔╝ 
    ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╔╝██║╚██╗ ██╔╝██╔══╝   ██╔██╗ 
    ██║ ╚████║╚██████╔╝███████╗██║ ╚═╝ ██║ ╚████╔╝ ███████╗██╗  ██╗
    ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
                   [ NOEMVEX WEB RECON V1.1 STEALTH HUNTER EDITION ]

 [*] Checking connection to https://testphp.vulnweb.com...
 [!] HTTPS failed. Attempting Protocol Downgrade (HTTP)...
 [+] Target is UP (via HTTP): http://testphp.vulnweb.com (Status: 200)

 --- [ PHASE 1: HEADER SECURITY ANALYSIS ] ---
 ┃  [WARN] Missing Header: Content-Security-Policy
 ┃  [INFO] Web Server Detected: nginx/1.19.0

 --- [ PHASE 2: HYBRID SUBDOMAIN DISCOVERY ] ---
 [*] Querying Certificate Transparency logs (Passive)...
 [!] Passive Enumeration Failed: Read timed out.
 [!] Switching to Active DNS Brute-Force (Fallback Mode)...
    No subdomains found in fallback list.

 --- [ PHASE 3: SENSITIVE FILE DISCOVERY ] ---
 [*] Using built-in default list (15 artifacts)...
 [CRITICAL] Found: http://testphp.vulnweb.com/login.php (200 OK) - Size: 5523b
 [CRITICAL] Found: http://testphp.vulnweb.com/admin/ (200 OK) - Size: 262b

 [√] RECONNAISSANCE COMPLETED.    
---

## ⚠️ Legal Disclaimer
**Usage of NOEMVEX-WEB for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability.**
**This project is designed for educational purposes and authorized security testing only.**

---
###  Developer
**Emre 'noemvex' Sahin**
*Cybersecurity Specialist & Tool Developer*
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/emresahin-sec) [![GitHub](https://img.shields.io/badge/GitHub-Follow-black?style=flat&logo=github)](https://github.com/noemvex)

