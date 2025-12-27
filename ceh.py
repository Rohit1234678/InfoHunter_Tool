#!/usr/bin/env python3
# ==========================================================
# InfoHunter v16 – Optimized Full Recon Framework
# Author : Rohit Madhav Sabale
# ==========================================================

import os, socket, subprocess, re, requests, ssl
import nmap, whois
from datetime import datetime
from tqdm import tqdm

OUTPUT_TXT = "infohunter_output.txt"
HTML_REPORT = "infohunter_report.html"

CVE_LIST = set()
EXPLOITS = {}

# ---------------- LOGO ----------------
def logo():
    print(r"""
 ██████╗ ██╗███╗   ██╗███████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██╔══██╗██║████╗  ██║██╔════╝██╔═══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██████╔╝██║██╔██╗ ██║█████╗  ██║   ██║███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══██╗██║██║╚██╗██║██╔══╝  ██║   ██║██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║  ██║██║██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
            InfoHunter v16 – FAST ⚡ | ULTRA-DEEP ☠️ Recon
""")

# ---------------- SAVE ----------------
def save(txt):
    with open(OUTPUT_TXT, "a", encoding="utf-8") as f:
        f.write(txt + "\n")

# ---------------- BASIC INFO ----------------
def basic_info(target):
    save("\n=== BASIC INFORMATION ===")
    ip = socket.gethostbyname(target)
    save(f"Target : {target}")
    save(f"IP      : {ip}")

    try:
        w = whois.whois(target)
        if w:
            for k,v in w.items():
                if v:
                    save(f"{k}: {v}")
    except:
        save("WHOIS lookup failed")

    try:
        geo = requests.get(f"https://ipapi.co/{ip}/json/", timeout=6).json()
        for k in ["city","region","country_name","org","asn"]:
            save(f"{k}: {geo.get(k)}")
    except:
        save("Geolocation failed")

    return ip

# ---------------- DNS ENUM ----------------
def dns_enum(domain):
    save("\n=== DNS ENUMERATION ===")
    for r in ["A","NS","MX","TXT"]:
        try:
            out = subprocess.check_output(
                ["nslookup", "-type="+r, domain],
                stderr=subprocess.DEVNULL
            ).decode()
            save(out)
        except:
            pass

# ---------------- WEB OSINT ----------------
def web_osint(target):
    save("\n=== WEB OSINT ===")
    urls = [
        f"http://{target}",
        f"http://{target}/robots.txt",
        f"http://{target}/sitemap.xml"
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=4)
            save(f"[{r.status_code}] {url}")
            if "Server" in r.headers:
                save(f"Server: {r.headers['Server']}")
        except:
            pass

# ---------------- NMAP SCAN ----------------
def nmap_scan(ip, deep):
    save("\n=== NMAP FULL PORT SCAN ===")
    nm = nmap.PortScanner()

    if not deep:
        args = "-p- -T4 --min-rate 1000 -sS -sV"
        save("Mode: FAST (All ports, no scripts)")
    else:
        args = "-p- -T4 --min-rate 800 -sS -sV -A --script vuln"
        save("Mode: ULTRA-DEEP (All ports + vuln scripts)")

    nm.scan(hosts=ip, arguments=args)

    if ip not in nm.all_hosts():
        save("No response from target")
        return

    for proto in nm[ip].all_protocols():
        save(f"\nProtocol: {proto}")
        for port in sorted(nm[ip][proto].keys()):
            info = nm[ip][proto][port]
            save(f"[OPEN] {port}/{proto} | {info['state']} | {info.get('name','')}")

            scripts = info.get("script")
            if scripts:
                for s, out in scripts.items():
                    save(f"[SCRIPT:{s}] {out}")
                    for cve in re.findall(r"CVE-\d{4}-\d{4,7}", out):
                        CVE_LIST.add(cve)

# ---------------- EXPLOITDB ----------------
def exploitdb_lookup():
    save("\n=== EXPLOITDB MAPPING ===")
    for cve in CVE_LIST:
        link = f"https://www.exploit-db.com/search?cve={cve}"
        EXPLOITS[cve] = link
        save(f"{cve} -> {link}")

# ---------------- HTML REPORT ----------------
def html_report(target, ip, mode):
    risk = min(100, len(CVE_LIST) * 10)

    html = f"""
<html>
<head>
<title>InfoHunter v16 SOC Report</title>
<style>
body {{background:#0b0f19;color:#e5e7eb;font-family:Segoe UI}}
h1,h2 {{color:#facc15}}
table {{width:100%;border-collapse:collapse}}
th,td {{border:1px solid #334155;padding:8px}}
th {{background:#020617}}
</style>
</head>
<body>

<h1>🛡️ InfoHunter v16 – SOC Report</h1>

<table>
<tr><th>Target</th><td>{target}</td></tr>
<tr><th>IP</th><td>{ip}</td></tr>
<tr><th>Mode</th><td>{mode}</td></tr>
<tr><th>Date</th><td>{datetime.now()}</td></tr>
<tr><th>Total CVEs</th><td>{len(CVE_LIST)}</td></tr>
<tr><th>Risk Score</th><td>{risk}%</td></tr>
</table>

<h2>🚨 CVE Intelligence</h2>
<table>
<tr><th>CVE</th><th>ExploitDB</th></tr>
"""
    for cve, link in EXPLOITS.items():
        html += f"<tr><td>{cve}</td><td><a href='{link}'>{link}</a></td></tr>"

    html += f"""
</table>

<h2>📄 Full Scan Output</h2>
<pre>{open(OUTPUT_TXT).read()}</pre>

</body>
</html>
"""
    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write(html)

# ---------------- MAIN ----------------
def main():
    os.system("clear")
    logo()

    if os.path.exists(OUTPUT_TXT):
        os.remove(OUTPUT_TXT)

    target = input("Enter Domain or IP: ").strip()

    print("\n1) FAST Scan\n2) ULTRA-DEEP Scan")
    deep = input("Choose mode: ") == "2"
    mode_name = "ULTRA-DEEP" if deep else "FAST"

    with tqdm(total=6, desc="InfoHunter Progress") as bar:
        ip = basic_info(target); bar.update(1)
        dns_enum(target); bar.update(1)
        web_osint(target); bar.update(1)
        nmap_scan(ip, deep); bar.update(1)
        exploitdb_lookup(); bar.update(1)

    html_report(target, ip, mode_name)

    print("\n[✔] Scan Completed")
    print("[✔] Report:", HTML_REPORT)

if __name__ == "__main__":
    main()
