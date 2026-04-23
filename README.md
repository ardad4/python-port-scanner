Python Port Scanner & Banner Grabber

A fast, multi-threaded Port Scanner and Banner Grabbing tool written purely in Python. This tool allows cybersecurity enthusiasts, penetration testers, and system administrators to scan networks, discover open ports, identify running services, and grab software banners to detect potential vulnerabilities.

Features

Multi-Threaded Scanning: Utilizes ThreadPoolExecutor to scan hundreds of ports concurrently, making it significantly faster than traditional sequential scanners.

Banner Grabbing: Automatically attempts to grab software versions and banners from open ports (e.g., SSH, HTTP, FTP).

Service Resolution: Resolves port numbers to their standard service names (e.g., Port 80 -> HTTP).

Domain Resolution: Supports both direct IP addresses and domain names (e.g., scanme.nmap.org).

Automated Reporting: Offers the ability to export the scan results into a clean, formatted .txt file for documentation and further analysis.

Prerequisites

This script requires Python 3.6+. It uses standard Python libraries, so no external dependencies (like pip install) are required!

Libraries used: socket, time, sys, datetime, concurrent.futures

Usage

Clone the repository:

git clone [https://github.com/yourusername/python-port-scanner.git](https://github.com/yourusername/python-port-scanner.git)
cd python-port-scanner


Run the script:

python port_scanner.py


Follow the interactive prompts:

Target IP or Domain (e.g., 192.168.1.1 or scanme.nmap.org): scanme.nmap.org
Start Port (Default 1): 1
End Port (Default 1024): 1000


 Example Output

----------------------------------------------------------------------
 PORT SCANNER 
     [Port Resolution, Banner Grabbing & Reporting]
----------------------------------------------------------------------
Target IP      : 45.33.32.156
Scan Range     : 1 - 1000
Start Time     : 2023-10-27 14:30:00
----------------------------------------------------------------------
Scanning in progress, please wait...

[+] Port 22    : OPEN (SSH) [Banner: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3]
[+] Port 80    : OPEN (HTTP) [Banner: HTTP/1.1 400 Bad Request | Server: nginx/1.4.6 (Ubuntu)...]

======================================================================
 📊 SCAN REPORT SUMMARY
======================================================================
Total of 2 open ports found:

PORT     | SERVICE         | VERSION / BANNER INFO
----------------------------------------------------------------------
22       | SSH             | SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.3
80       | HTTP            | HTTP/1.1 400 Bad Request | Server: nginx/1.4.6 (Ubuntu)...
----------------------------------------------------------------------
⏳ Total scan time: 4.25 seconds

Would you like to save these results to a .txt file? (Y/N): y

[✔] Report successfully saved: scan_report_45_33_32_156_20231027_143004.txt


 Legal Disclaimer

FOR EDUCATIONAL PURPOSES ONLY. This tool is intended for learning about network security, socket programming, and system administration. Do not use this tool to scan networks, IP addresses, or domains that you do not own or do not have explicit written permission to test. Unauthorized port scanning can be considered a cyber attack and is illegal in many jurisdictions.

License

Distributed under the MIT License. See LICENSE for more information.