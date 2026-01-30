# NOEMVEX-WEB v1.0 [HUNTER EDITION]
![Python](https://img.shields.io/badge/Python-3.x-blue) ![License](https://img.shields.io/badge/License-MIT-grey) ![Focus](https://img.shields.io/badge/Focus-Web%20Recon-yellow) ![Type](https://img.shields.io/badge/Edition-Red%20Edition-red)

> **"Hunt the Assets, Map the Surface."**
> Lightweight Web Reconnaissance engine designed for passive subdomain enumeration, security header analysis, and sensitive file discovery.
> ⚠️ **Disclaimer:** This tool is for educational purposes only. [Read the full Legal Disclaimer](#️-legal-disclaimer)

---
##  About
**NOEMVEX-WEB** is a fast and efficient web reconnaissance tool developed to automate the initial discovery phase of a web application engagement. By leveraging passive certificate transparency logs, it maps out the target's subdomains without ever interacting directly with the secondary assets. Furthermore, it audits HTTP response headers for missing security controls and performs a high-speed multi-threaded scan for sensitive artifacts such as `.env`, `.git`, or backup files that often lead to critical information disclosure.



##  Capabilities
* **Passive Subdomain Enumeration:** Queries `crt.sh` to extract subdomains from SSL/TLS certificate logs, ensuring zero-touch discovery.
* **Security Header Audit:** Analyzes critical headers like CSP, HSTS, and X-Frame-Options to evaluate the target's hardening posture.
* **Sensitive File Discovery:** Multi-threaded fuzzing engine targeting high-value files (.env, wp-config, etc.) and restricted directories.
* **Web Server Identification:** Automatically extracts server banners to assist in version-specific vulnerability research.
* **Smart URL Normalization:** Handles both raw domains and full URLs, ensuring the engine adapts to the input format.

---
##  Usage

### 1. Requirements
Standard Python 3.x is required. Ensure you have the `requests` library installed:
pip install requests

### 2. Execution
# Clone the Hunter Engine
git clone https://github.com/noemvex/NOEMVEX-WEB.git
cd NOEMVEX-WEB

# Run recon against a target domain
python3 noemvex_web.py -u example.com

---

##  Output Preview

    ███╗   ██╗ ██████╗ ███████╗███╗   ███╗██╗   ██╗███████╗██╗  ██╗
    ████╗  ██║██╔═══██╗██╔════╝████╗ ████║██║   ██║██╔════╝╚██╗██╔╝
    ██╔██╗ ██║██║   ██║█████╗  ██╔████╔██║██║   ██║█████╗   ╚███╔╝ 
    ██║╚██╗██║██║   ██║██╔══╝  ██║╚██╔╝██║╚██╗ ██╔╝██╔══╝   ██╔██╗ 
    ██║ ╚████║╚██████╔╝███████╗██║ ╚═╝ ██║ ╚████╔╝ ███████╗██╗  ██╗
    ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝
                   [ NOEMVEX WEB RECON V1.0 HUNTER EDITION ]

    [+] Target is UP: https://example.com (Status: 200)

    --- [ PHASE 1: HEADER SECURITY ANALYSIS ] ---
    ┃  [OK] Header Found: Content-Security-Policy
    ┃  [WARN] Missing Header: Strict-Transport-Security
    ┃  [INFO] Web Server Detected: nginx/1.18.0

    --- [ PHASE 2: PASSIVE SUBDOMAIN ENUM (crt.sh) ] ---
    [*] Querying Certificate Transparency logs...
      -> api.example.com
      -> dev.example.com
      -> vpn.example.com
    [+] Total Subdomains Found: 3

    --- [ PHASE 3: SENSITIVE FILE DISCOVERY ] ---
    [*] Fuzzing for 14 critical artifacts...
    [CRITICAL] Found: https://example.com/.env (200 OK)
    [FORBIDDEN] Exists: https://example.com/admin/ (403)

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

