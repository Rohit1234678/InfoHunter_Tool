#!/usr/bin/env python3
import nmap
import whois
import socket
import requests
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
    with open("infohunter_output.txt", "a", encoding="utf-8") as f:
        f.write(data + "\n")

# ---------------- OSINT INFO ----------------
def osint_info(domain):
    print("\n[+] OSINT Information")
    save("\n[OSINT INFORMATION]")
    for path in ["robots.txt", "sitemap.xml"]:
        try:
            url = f"http://{domain}/{path}"
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                save(f"[FOUND] {url}")
                print(f"[FOUND] {url}")
        except:
            pass

# ---------------- DNS ENUMERATION ----------------
def dns_enum(domain):
    print("\n[+] DNS Enumeration")
    save("\n[DNS ENUMERATION]")
    for r in ["A", "MX", "NS", "TXT"]:
        try:
            result = subprocess.check_output(
                ["nslookup", "-type=" + r, domain],
                stderr=subprocess.DEVNULL
            ).decode()
            print(result)
            save(result)
        except:
            pass

# ---------------- SUBDOMAIN ENUMERATION ----------------
def subdomain_enum(domain):
    print("\n[+] Subdomain Enumeration")
    save("\n[SUBDOMAIN ENUMERATION]")
    subs = ["www","mail","ftp","dev","test","api","admin","portal","blog"]
    for sub in subs:
        try:
            host = f"{sub}.{domain}"
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
    paths = ["admin","login","dashboard","backup","uploads","config"]
    for p in paths:
        try:
            url = f"http://{domain}/{p}"
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

# ================= MAIN =================
logo()
target = input("Enter Target IP / Domain: ").strip()
ip = socket.gethostbyname(target)

# ================= ATTACK MENU =================
while True:
    print("""
================ InfoHunter Attack Menu ================

1) OSINT Information
2) DNS Enumeration
3) Subdomain Enumeration
4) Directory Enumeration
5) Technology Detection
6) Email Enumeration
7) Admin Panel Detection
8) Service Enumeration
9) Exit

========================================================
""")

    ch = input("Select option: ")

    if ch == "1":
        osint_info(target)
    elif ch == "2":
        dns_enum(target)
    elif ch == "3":
        subdomain_enum(target)
    elif ch == "4":
        dir_enum(target)
    elif ch == "5":
        tech_detection(target)
    elif ch == "6":
        email_enum(target)
    elif ch == "7":
        admin_panel_check(target)
    elif ch == "8":
        service_enum(ip)
    elif ch == "9":
        print("\n[+] Exiting InfoHunter")
        break
    else:
        print("[-] Invalid option")



