License: [MIT](LICENSE) · SPDX: MIT
# WebFerseners
## 🕵️‍♂️ Modular Web Vulnerability Scanner (Educational)

A modular, Python-based **web vulnerability scanner** built for learning and authorized testing.  
Detects **SQL Injection** (error & time), **Reflected XSS**, **Missing Security Headers**, and **sensitive directories**.  
Optional integration with **sqlmap** for deeper SQLi confirmation.

> ⚠️ **Only** run this tool against systems you own or have explicit written permission to test.

---

## Features

- BFS crawling with configurable depth  
- SQL Injection detection:
  - Error-based
  - Time-based (heuristic)
  - Optional sqlmap confirmation (`--use-sqlmap`)
- Reflected XSS detection (query-based)
- Missing security headers check
- Directory enumeration (threaded)
- JSON & plain-text report outputs
- Multithreaded scanner for speed

---

## Quick Start (Linux)

> Tested on Debian/Ubuntu/Kali. Commands assume `bash` and Python 3.8+.

### 1. Clone repo
```bash
git clone https://github.com/<your-username>/Modular-Web-Scanner.git
cd Modular-Web-Scanner
```
2. Create & activate a Python virtual environment
```bash 
python3 -m venv venv
source venv/bin/activate
```
3. Install Python dependencies
``` bash
pip install -r requirements.txt
```
Sqlmap
sqlmap (recommended for advanced SQLi checks)
Option A — Install from package manager (quick):

```bash
sudo apt update
sudo apt install sqlmap -y
```
Option B — Install latest from GitHub (recommended):

```bash
git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
# optional: make sqlmap runnable from anywhere
sudo ln -s "$(pwd)/sqlmap/sqlmap.py" /usr/local/bin/sqlmap
```
Verify:

```bash
sqlmap --version
```

Usage
Replace http://target/ with the URL you are authorized to test.

Basic (full scan)
```bash
python3 webscanner.py -u http://target/
```
SQLi only
```bash
python3 webscanner.py -u http://target/login -m sqli
```
SQLi with sqlmap confirmation
```bash
python3 webscanner_with_sqlmap.py -u http://target/login -m sqli --use-sqlmap
```
Or if your main script supports the flag:

```bash
python3 webscanner.py -u http://target/login -m sqli --use-sqlmap
```
XSS only
```bash
python3 webscanner.py -u "http://target/search?q=test" -m xss
```
Directory enumeration with built-in wordlist
```bash
python3 webscanner.py -u http://target/ -m dirs -w webscanner/big.txt
```
Save human-readable report
```bash
python3 webscanner.py -u http://target/ -o report.txt
```
Scanner automatically writes report.json (structured results) in the current directory.

How time-based detection works
The scanner measures response time (elapsed) after injecting payloads.
If a payload causes a delay longer than a threshold (default: 4 s), the scanner flags a time-based SQLi finding:

```text
SQL Injection (Time-Based - Form) — evidence: Delay 5.0s
You may customize payload lists in the script (e.g., add SLEEP(5) for specific tests). Only use such payloads on systems you control or have permission to test.
```

Output & Reports
Console: colorized findings (High / Medium / Low)

report.json: deduplicated structured findings (url, type, evidence, payload, severity)

Optional plain-text file (via -o)

Example report.json entry:

```json
{
  "url": "http://target/login",
  "type": "SQL Injection (Error-Based - Form)",
  "evidence": "sqlite3.operationalerror",
  "payload": {"username": "'","password":"password"},
  "severity": "High"
}
```
Security & Legal
This tool is for educational & authorized penetration testing only.
Do not use it against systems you do not own or for which you do not have explicit written permission. The author is not responsible for misuse.

Contributing

Contributions welcome — open issues and PRs for features, bugfixes, or improved detection heuristics.
If you incorporate third-party code, include attribution and ensure licensing compliance.

License

This project is released under MIT. See LICENSE for details.

Author
Athul — Cybersecurity enthusiast
GitHub: https://github.com/AK-120
Contact: athulkrishnanotp@gmail.com
