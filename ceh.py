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
 ██╗███╗   ██╗███████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██║████╗  ██║██╔════╝██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██║██╔██╗ ██║█████╗  ██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
        InfoHunter – Golden Reconnaissance Tool
                    Author: Rohit Sabale
""")

# ---------------- SAVE OUTPUT ----------------
def save(data):
    with open("autoreconx_output.txt", "a", encoding="utf-8") as f:
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

# ---------------- DNS ENUMERATION ----------------
def dns_enum(domain):
    print("\n[+] DNS Enumeration")
    save("\n[DNS ENUMERATION]")
    records = ["A", "MX", "NS", "TXT"]
    for r in records:
        try:
            result = subprocess.check_output(
                ["nslookup", "-type=" + r, domain],
                stderr=subprocess.DEVNULL
            ).decode()
            print(f"\n--- {r} Records ---")
            print(result)
            save(result)
        except:
            print(f"[-] {r} lookup failed")

# ---------------- SUBDOMAIN ENUMERATION ----------------
def subdomain_enum(domain):
    print("\n[+] Subdomain Enumeration")
    save("\n[SUBDOMAIN ENUMERATION]")
    subs = ["www","mail","ftp","dev","test","api","admin","portal","blog"]
    for sub in subs:
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            data = f"[FOUND] {host} -> {ip}"
            print(data)
            save(data)
        except:
            pass

# ---------------- DIRECTORY ENUMERATION ----------------
def dir_enum(domain):
    print("\n[+] Directory Enumeration")
    save("\n[DIRECTORY ENUMERATION]")
    paths = ["admin","login","test","backup","uploads","config"]
    for p in paths:
        url = f"http://{domain}/{p}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code in [200,301,403]:
                data = f"[FOUND] {url} ({r.status_code})"
                print(data)
                save(data)
        except:
            pass
# ---------------- TECHNOLOGY DETECTION ----------------
def tech_detection(domain):
    print("\n[+] Technology Detection")
    save("\n[TECHNOLOGY DETECTION]")
    try:
        r = requests.get("http://" + domain, timeout=5)
        save(f"Server: {r.headers.get('Server','Unknown')}")
        save(f"X-Powered-By: {r.headers.get('X-Powered-By','Unknown')}")
        if "wp-content" in r.text:
            save("CMS Detected: WordPress")
            print("[+] CMS Detected: WordPress")
    except:
        pass

# ---------------- EMAIL ENUMERATION ----------------
def email_enum(domain):
    print("\n[+] Email Enumeration")
    save("\n[EMAIL ENUMERATION]")
    for e in ["admin","support","info","contact"]:
        data = f"Possible Email: {e}@{domain}"
        print(data)
        save(data)

# ---------------- ADMIN PANEL DETECTION ----------------
def admin_panel_check(domain):
    print("\n[+] Admin Panel Detection")
    save("\n[ADMIN PANEL DETECTION]")
    paths = ["admin","admin/login","cpanel","login","dashboard"]
    for p in paths:
        try:
            url = f"http://{domain}/{p}"
            r = requests.get(url, timeout=3)
            if r.status_code in [200,301,403]:
                print(f"[FOUND] {url}")
                save(f"[FOUND] {url}")
        except:
            pass
# ---------------- HTTP HEADER ATTACK ----------------
def http_header_attack(domain):
    print("\n[+] HTTP Header Information")
    save("\n[HTTP HEADER INFORMATION]")
    try:
        r = requests.get("http://" + domain, timeout=5)
        for h in r.headers:
            line = f"{h}: {r.headers[h]}"
            print(line)
            save(line)
    except:
        print("[-] HTTP request failed")

# ---------------- SERVICE ENUMERATION ----------------
def service_enum(ip):
    print("\n[+] Service Enumeration")
    save("\n[SERVICE ENUMERATION]")
    ports = [21,22,23,25,53,80,110,139,443,445,3306]
    for port in ports:
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, port))
            data = f"[OPEN] Port {port}"
            print(data)
            save(data)
            s.close()
        except:
            pass

# ---------------- MAIN ----------------
logo()

target = input("Enter Target IP / Domain: ").strip()
time = datetime.now()

print("\n[+] Target:", target)
save(f"\nTarget: {target}\nScan Time: {time}")

# DNS → IP
ip = socket.gethostbyname(target)
print("[+] IP Address:", ip)
save(f"IP Address: {ip}")

# WHOIS
print("\n[+] WHOIS Information")
try:
    w = whois.whois(target)
    print("Registrar:", w.registrar)
    save(f"Registrar: {w.registrar}")
except:
    print("WHOIS failed")

# GEO
print("\n[+] Geo Location")
geo = requests.get(f"http://ip-api.com/json/{ip}").json()
for k in ["country","regionName","city","isp"]:
    print(f"{k}: {geo.get(k)}")
    save(f"{k}: {geo.get(k)}")

# ---------------- NMAP SCANS ----------------
print("""
Scan Profiles:
1) Quick Scan (Fast TCP)
2) Intense Scan (Fast + Service + OS) [Root]
3) Full TCP Scan (All Ports – Optimized)
4) UDP Scan (Top UDP Ports)
""")

choice = input("Choose Scan: ").strip()
scanner = nmap.PortScanner()

try:
    if choice == "1":
        # FAST common ports + service detection
        scanner.scan(ip, arguments="-sS -sV --top-ports 1000 -T4")

    elif choice == "2":
        # Faster intense scan (optimized)
        scanner.scan(ip, arguments="-sS -sV -O --top-ports 2000 -T4")

    elif choice == "3":
        # Full TCP scan but optimized (faster than 0-65535)
        scanner.scan(ip, arguments="-sS -sV -p- --min-rate 500 -T4")

    elif choice == "4":
        # UDP scan (TOP UDP ports – realistic & fast)
        scanner.scan(ip, arguments="-sU --top-ports 100 -T4")

    else:
        print("Invalid choice")
        exit()

except Exception as e:
    print("[-] Nmap scan failed:", e)
    exit()

if ip not in scanner.all_hosts():
    print("Scan failed or host unreachable")
    exit()

# ---------------- ATTACK MENU ----------------
while True:
    print("""
Recon Attack Modules:
1) DNS Enumeration
2) Subdomain Enumeration
3) Directory Enumeration
4) Technology Detection
5) Email Enumeration
6) Admin Panel
7) HTTP Header Attack
8) Service Enumeration
9) Exit
""")

    ch = input("Select option: ")

    if ch == "1":
        dns_enum(target)
    elif ch == "2":
        subdomain_enum(target)
    elif ch == "3":
        dir_enum(target)
    elif ch == "4":
         tech_detection(target)
    elif ch == "5":
        email_enum(target)
    elif ch == "6":
        admin_panel_check(target)
    elif ch == "7":
        http_header_attack(target)
    elif ch == "8":
        service_enum(target)
    elif ch == "9":
          print("\n[+] Exiting InfoHunter")
    else:
        break

# ---------------- HTML REPORT ----------------
html = f"""
<!DOCTYPE html>
<html>
<head>
<title>AutoReconX Report</title>
<style>
body {{ background:#0f172a; color:#e5e7eb; font-family:Arial; }}
h1 {{ color:#22c55e; }}
pre {{ background:#020617; padding:15px; border-radius:8px; }}
</style>
</head>
<body>
<h1>AutoReconX Scan Report</h1>
<p><b>Target:</b> {target}</p>
<p><b>IP:</b> {ip}</p>
<p><b>Date:</b> {time}</p>
<pre>
"""

if os.path.exists("autoreconx_output.txt"):
    html += open("autoreconx_output.txt", encoding="utf-8").read()
else:
    html += "No output available"

html += """
</pre>
</body>
</html>
"""

with open("report.html","w",encoding="utf-8") as f:
    f.write(html)

print("\n[+] HTML report generated: report.html")

# PDF
try:
    subprocess.call(["wkhtmltopdf","report.html","report.pdf"])
    print("[+] PDF report generated: report.pdf")
except:
    print("PDF generation failed")

