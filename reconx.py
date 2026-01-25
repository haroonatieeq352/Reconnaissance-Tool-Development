#!/usr/bin/env python3

import argparse
import subprocess
import requests
import socket
import datetime
import json
import os

# =========================
# SETUP
# =========================
OUTPUT_DIR = "reports"
os.makedirs(OUTPUT_DIR, exist_ok=True)


def log(msg, level="INFO"):
    print(f"[{level}] {msg}")


def safe_filename(value):
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in value)


# =========================
# RECON FUNCTIONS
# =========================
def whois_lookup(domain):
    log("Running WHOIS lookup")
    return subprocess.getoutput(f"whois {domain}")


def dns_enum(domain):
    log("Enumerating DNS records")
    records = {}
    for r in ["A", "MX", "TXT", "NS"]:
        records[r] = subprocess.getoutput(f"dig {domain} {r} +short")
    return records


def crtsh_enum(domain):
    log("Fetching subdomains from crt.sh")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        res = requests.get(url, timeout=10)
        return list({e["name_value"] for e in res.json()})
    except:
        return []


def otx_enum(domain):
    log("Fetching subdomains from AlienVault OTX")
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        res = requests.get(url, timeout=10).json()
        return list({e["hostname"] for e in res.get("passive_dns", [])})
    except:
        return []


def port_scan(domain):
    log("Running Nmap scan")
    return subprocess.getoutput(f"nmap -sS -Pn -T4 {domain}")


def banner_grab(domain):
    log("Banner grabbing")
    banners = {}
    for port in [21, 22, 80, 443]:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((domain, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banners[port] = s.recv(1024).decode(errors="ignore")
            s.close()
        except:
            banners[port] = "No response"
    return banners


def tech_detect(domain):
    log("Detecting technologies")
    return subprocess.getoutput(f"whatweb {domain}")


# =========================
# HTML REPORT GENERATOR
# =========================
def generate_report(domain, data):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_domain = safe_filename(domain)
    report_file = f"{OUTPUT_DIR}/{safe_domain}_report.html"

    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>ReconX Report - {domain}</title>
<style>
body {{
    font-family: Arial, sans-serif;
    background-color: #f4f6f8;
    margin: 0;
    padding: 20px;
}}
.container {{
    max-width: 1100px;
    margin: auto;
    background: white;
    padding: 20px;
    border-radius: 6px;
}}
h1 {{
    color: #2c3e50;
}}
h2 {{
    background: #2c3e50;
    color: white;
    padding: 10px;
    border-radius: 4px;
}}
pre {{
    background: #1e1e1e;
    color: #dcdcdc;
    padding: 15px;
    overflow-x: auto;
    border-radius: 4px;
}}
.footer {{
    text-align: center;
    color: gray;
    margin-top: 20px;
    font-size: 12px;
}}
</style>
</head>
<body>

<div class="container">
<h1>ReconX Reconnaissance Report</h1>
<p><strong>Target:</strong> {domain}</p>
<p><strong>Generated:</strong> {timestamp}</p>

<hr>
"""

    for section, content in data.items():
        html += f"<h2>{section.upper()}</h2><pre>{content}</pre>"

    html += """
<div class="footer">
ReconX • Automated Recon Tool
</div>
</div>

</body>
</html>
"""

    with open(report_file, "w", encoding="utf-8") as f:
        f.write(html)

    log(f"HTML report saved: {report_file}")
    log(f"Open in browser: file://{os.path.abspath(report_file)}")


# =========================
# MAIN
# =========================
def main():
    parser = argparse.ArgumentParser(description="ReconX - Custom Recon Tool")
    parser.add_argument("domain", help="Target domain or URL")
    parser.add_argument("--whois", action="store_true")
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--subdomains", action="store_true")
    parser.add_argument("--active", action="store_true")
    parser.add_argument("--all", action="store_true")

    args = parser.parse_args()
    results = {}

    if args.whois or args.all:
        results["whois"] = whois_lookup(args.domain)

    if args.dns or args.all:
        results["dns"] = json.dumps(dns_enum(args.domain), indent=2)

    if args.subdomains or args.all:
        subs = set(crtsh_enum(args.domain) + otx_enum(args.domain))
        results["subdomains"] = "\n".join(subs)

    if args.active or args.all:
        results["nmap"] = port_scan(args.domain)
        results["banners"] = json.dumps(banner_grab(args.domain), indent=2)
        results["technologies"] = tech_detect(args.domain)

    generate_report(args.domain, results)


if __name__ == "__main__":
    main()




