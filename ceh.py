#!/usr/bin/env python3
import nmap
import whois
import socket
import requests
import os
import subprocess
from datetime import datetime

# ---------------- LOGO ----------------
def logo():
    print("""
 ███████╗██╗███╗   ██╗███████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
 ██╔════╝██║████╗  ██║██╔════╝██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 █████╗  ██║██╔██╗ ██║█████╗  ██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══╝  ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║     ██║██║ ╚████║███████╗╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝     ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
        InfoHunter – Advanced Reconnaissance Tool
              Author: Rohit Madhav Sabale
""")

# ---------------- SAVE OUTPUT ----------------
def save(data):
    with open("infohunter_output.txt", "a", encoding="utf-8") as f:
        f.write(data + "\n")

# ---------------- BANNER GRABBING ----------------
def banner_grab(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors="ignore")
        s.close()
        return banner.strip()
    except:
        return "No Banner"

# ---------------- OSINT INFO ----------------
def osint_info(domain):
    print("\n[+] OSINT Information Gathering")
    save("\n[OSINT INFORMATION]")
    for path in ["robots.txt", "sitemap.xml"]:
        try:
            url = f"http://{domain}/{path}"
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                save(f"[FOUND] {url}")
        except:
            pass

# ---------------- DNS ENUMERATION ----------------
def dns_enum(domain):
    save("\n[DNS ENUMERATION]")
    for r in ["A","MX","NS","TXT"]:
        try:
            result = subprocess.check_output(
                ["nslookup", "-type=" + r, domain],
                stderr=subprocess.DEVNULL
            ).decode()
            save(result)
        except:
            pass

# ---------------- SUBDOMAIN ENUMERATION ----------------
def subdomain_enum(domain):
    save("\n[SUBDOMAIN ENUMERATION]")
    subs = ["www","mail","ftp","dev","test","api","admin","portal","blog"]
    for sub in subs:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            save(f"[FOUND] {host} -> {ip}")
        except:
            pass

# ---------------- DIRECTORY ENUMERATION ----------------
def dir_enum(domain):
    save("\n[DIRECTORY ENUMERATION]")
    paths = ["admin","login","dashboard","backup","uploads","config"]
    for p in paths:
        try:
            url = f"http://{domain}/{p}"
            r = requests.get(url, timeout=3)
            if r.status_code in [200,301,403]:
                save(f"[FOUND] {url} ({r.status_code})")
        except:
            pass

# ---------------- TECHNOLOGY DETECTION ----------------
def tech_detection(domain):
    save("\n[TECHNOLOGY DETECTION]")
    try:
        r = requests.get("http://" + domain, timeout=5)
        save(f"Server: {r.headers.get('Server','Unknown')}")
        save(f"X-Powered-By: {r.headers.get('X-Powered-By','Unknown')}")
        if "wp-content" in r.text:
            save("CMS Detected: WordPress")
    except:
        pass

# ---------------- EMAIL ENUMERATION ----------------
def email_enum(domain):
    save("\n[EMAIL ENUMERATION]")
    for e in ["admin","support","info","contact"]:
        save(f"Possible Email: {e}@{domain}")

# ---------------- ADMIN PANEL CHECK ----------------
def admin_panel_check(domain):
    save("\n[ADMIN PANEL CHECK]")
    paths = ["admin","admin/login","cpanel","login","dashboard"]
    for p in paths:
        try:
            url = f"http://{domain}/{p}"
            r = requests.get(url, timeout=3)
            if r.status_code in [200,301,403]:
                save(f"[FOUND] {url}")
        except:
            pass

# ---------------- SERVICE ENUM ----------------
def service_enum(ip):
    save("\n[SERVICE ENUMERATION]")
    ports = [21,22,23,25,53,80,110,139,443,445,3306]
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, port))
            save(f"[OPEN] Port {port}")
            s.close()
        except:
            pass

# ---------------- MAIN ----------------
logo()
target = input("Enter Target IP / Domain: ").strip()
time = datetime.now()

save(f"\nTarget: {target}\nScan Time: {time}")

ip = socket.gethostbyname(target)
save(f"IP Address: {ip}")

try:
    w = whois.whois(target)
    save(f"Registrar: {w.registrar}")
except:
    pass

geo = requests.get(f"http://ip-api.com/json/{ip}").json()
for k in ["country","regionName","city","isp"]:
    save(f"{k}: {geo.get(k)}")

print("""
Scan Profiles:
1) Quick Scan
2) Intense Scan (sudo)
3) Full TCP Scan
4) UDP Scan
""")

scanner = nmap.PortScanner()
choice = input("Choose Scan: ")

if choice == "1":
    scanner.scan(ip, arguments="-T4 -F")
elif choice == "2":
    scanner.scan(ip, arguments="-sS -sV -O -Pn --privileged -T4")
elif choice == "3":
    scanner.scan(ip, arguments="-sS -p- -Pn --privileged --min-rate 1000")
elif choice == "4":
    scanner.scan(ip, arguments="-sU --top-ports 50 --privileged")
else:
    exit()

for proto in scanner[ip].all_protocols():
    for port in scanner[ip][proto]:
        state = scanner[ip][proto][port]["state"]
        banner = banner_grab(ip, port)
        save(f"Port {port}/{proto} - {state} | Banner: {banner}")

# ---------------- ATTACK MENU ----------------
while True:
    print("""
Recon Modules:
1) OSINT Info
2) DNS Enum
3) Subdomain Enum
4) Directory Enum
5) Tech Detection
6) Email Enum
7) Admin Panel Check
8) Service Enum
9) Exit
""")
    ch = input("Select: ")

    if ch == "1": osint_info(target)
    elif ch == "2": dns_enum(target)
    elif ch == "3": subdomain_enum(target)
    elif ch == "4": dir_enum(target)
    elif ch == "5": tech_detection(target)
    elif ch == "6": email_enum(target)
    elif ch == "7": admin_panel_check(target)
    elif ch == "8": service_enum(ip)
    else: break

# ---------------- HTML REPORT ----------------
html = f"""
<html><head>
<title>InfoHunter Report</title>
<style>
body {{ background:black;color:gold;font-family:Arial; }}
pre {{ background:#111;padding:15px;border-radius:8px; }}
</style></head><body>
<h1>InfoHunter Scan Report</h1>
<p>Target: {target}</p>
<p>IP: {ip}</p>
<p>Date: {time}</p>
<pre>{open("infohunter_output.txt").read()}</pre>
</body></html>
"""

open("report.html","w").write(html)
subprocess.call(["wkhtmltopdf","report.html","report.pdf"])

print("\n[+] Reports generated: report.html & report.pdf")

except:
    print("PDF generation failed")

