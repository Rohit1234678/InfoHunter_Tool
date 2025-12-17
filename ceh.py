#!/usr/bin/env python3
import nmap
import whois
import socket
import requests
import subprocess
import os
from datetime import datetime

OUTPUT_FILE = "infohunter_output.txt"

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
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(data + "\n")

# ---------------- BASIC INFO ----------------
def basic_info(target):
    print("\n[+] Resolving Target...")
    ip = socket.gethostbyname(target)
    print("[+] IP Address:", ip)
    save(f"Target: {target}")
    save(f"IP Address: {ip}")

    print("\n[+] WHOIS Information")
    try:
        w = whois.whois(target)
        print("Registrar:", w.registrar)
        save(f"Registrar: {w.registrar}")
    except:
        print("WHOIS lookup failed")

    print("\n[+] Geo Location")
    geo = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
    for k in ["country", "regionName", "city", "isp"]:
        print(f"{k}: {geo.get(k)}")
        save(f"{k}: {geo.get(k)}")

    return ip

# ---------------- NMAP SCAN ----------------
def nmap_scan(ip):
    print("""
Scan Profiles:
1) Quick Scan (Fast)
2) Intense Scan (Service + OS)
3) Full TCP Scan
4) UDP Scan
""")

    choice = input("Choose Scan: ").strip()
    scanner = nmap.PortScanner()

    if choice == "1":
        args = "-sS -sV --top-ports 1000 -T4"
    elif choice == "2":
        args = "-sS -sV -O --top-ports 2000 -T4"
    elif choice == "3":
        args = "-sS -sV -p- --min-rate 500 -T4"
    elif choice == "4":
        args = "-sU --top-ports 100 -T4"
    else:
        print("Invalid option")
        return

    print("\n[+] Running Nmap Scan...")
    scanner.scan(ip, arguments=args)

    if ip not in scanner.all_hosts():
        print("Scan failed")
        return

    print("\n[+] Open Ports & Services")
    save("\n[OPEN PORTS & SERVICES]")

    for proto in scanner[ip].all_protocols():
        for port in sorted(scanner[ip][proto]):
            info = scanner[ip][proto][port]
            line = f"{port}/{proto} | {info.get('state')} | {info.get('name')} {info.get('product','')} {info.get('version','')}"
            print(line)
            save(line)

# ---------------- ENUMERATION MODULES ----------------
def dns_enum(domain):
    print("\n[+] DNS Enumeration")
    for r in ["A", "MX", "NS", "TXT"]:
        try:
            result = subprocess.check_output(["nslookup", "-type="+r, domain]).decode()
            print(result)
            save(result)
        except:
            pass

def subdomain_enum(domain):
    print("\n[+] Subdomain Enumeration")
    for sub in ["www","mail","ftp","dev","test","api","admin","portal"]:
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            line = f"{sub}.{domain} -> {ip}"
            print(line)
            save(line)
        except:
            pass

def dir_enum(domain):
    print("\n[+] Directory Enumeration")
    for p in ["admin","login","dashboard","backup","uploads"]:
        try:
            url = f"http://{domain}/{p}"
            r = requests.get(url, timeout=3)
            if r.status_code in [200,301,403]:
                print("[FOUND]", url)
                save(f"[FOUND] {url}")
        except:
            pass

def tech_detection(domain):
    print("\n[+] Technology Detection")
    try:
        r = requests.get("http://" + domain, timeout=5)
        print("Server:", r.headers.get("Server"))
        save(f"Server: {r.headers.get('Server')}")
        if "wp-content" in r.text:
            print("CMS: WordPress")
            save("CMS: WordPress")
    except:
        pass

def email_enum(domain):
    print("\n[+] Email Enumeration")
    for e in ["admin","support","info","contact"]:
        line = f"{e}@{domain}"
        print(line)
        save(line)

def admin_panel(domain):
    print("\n[+] Admin Panel Detection")
    for p in ["admin","admin/login","cpanel","dashboard"]:
        try:
            url = f"http://{domain}/{p}"
            r = requests.get(url, timeout=3)
            if r.status_code in [200,301,403]:
                print("[FOUND]", url)
                save(f"[FOUND] {url}")
        except:
            pass

# ---------------- ENUM MENU ----------------
def enumeration_menu(target, ip):
    while True:
        print("""
Enumeration Modules:
1) DNS Enumeration
2) Subdomain Enumeration
3) Directory Enumeration
4) Technology Detection
5) Email Enumeration
6) Admin Panel Detection
7) Exit
""")
        ch = input("Select option: ")

        if ch == "1": dns_enum(target)
        elif ch == "2": subdomain_enum(target)
        elif ch == "3": dir_enum(target)
        elif ch == "4": tech_detection(target)
        elif ch == "5": email_enum(target)
        elif ch == "6": admin_panel(target)
        else: break

# ---------------- MAIN ----------------
logo()
target = input("Enter Target IP / Domain: ").strip()
save(f"\nScan Time: {datetime.now()}")

ip = basic_info(target)
nmap_scan(ip)
enumeration_menu(target, ip)

print("\n[+] Scan Completed. Output saved to infohunter_output.txt")
