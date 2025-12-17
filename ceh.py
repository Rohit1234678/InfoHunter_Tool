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

# ---------------- HTTP HEADER INFO ----------------
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
