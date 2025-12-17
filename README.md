# 🟡 InfoHunter – Advanced Information Gathering Tool

InfoHunter is a Zenmap-inspired automated reconnaissance and enumeration tool written in Python.
It performs information gathering using a single input (IP address or Domain name) and is designed
for CEH, cybersecurity training, and academic projects.

## 🚀 Features
- Menu-based CLI interface
- Zenmap-style scan profiles
- Nmap port & service scanning
- Banner grabbing
- WHOIS lookup
- DNS resolution
- Geo-location tracking
- Subdomain enumeration
- Directory enumeration
- HTTP header information
- Save output to file
- HTML & PDF report generation
- Kali Linux compatible

## 📦 Requirements
- Python 3.x
- Nmap
- wkhtmltopdf
- Libraries:
  - python-nmap
  - requests
  - python-whois

## ▶️ Usage (Kali Linux)
```bash
sudo apt update
sudo apt install nmap whois wkhtmltopdf python3-pip -y
pip3 install python-nmap requests python-whois
python3 infohunter.py

⚠️ Legal Disclaimer

This tool is intended for educational and authorized testing only.
Do not scan systems without permission.

👨‍💻 Author
 
 # Rohit Madhav Sabale

