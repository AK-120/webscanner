#!/usr/bin/env python3
"""
Advanced Modular Web Vulnerability Scanner WITH optional sqlmap integration.

Features:
- SQL Injection (Error + Time)
- XSS (Reflected)
- Missing Security Headers
- Directory Enumeration
- Crawl and Report
- Optional: call sqlmap subprocess per-target to confirm SQLi

Usage:
  python3 webscanner_with_sqlmap.py -u http://127.0.0.1:5000/ --mode sqli --use-sqlmap
"""

import argparse
import requests
import concurrent.futures
import re
import time
import os
import json
import subprocess
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from tqdm import tqdm
from colorama import Fore, Style, init
import warnings

init(autoreset=True)
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

# ---------------- CONFIG ----------------
HEADERS = {"User-Agent": "WebScannerPro/3.2"}
TIMEOUT = 10
THREADS = 12
SQLI_PAYLOADS = ["'", "\"", "' OR 1=1 --", "' OR 'a'='a", "\" OR \"1\"=\"1"]
XSS_PAYLOADS = [
    "<script>alert(1337)</script>",
    "\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "sqlite3.operationalerror",
    "unclosed quotation mark",
    "syntax error at or near",
    "traceback (most recent call last)",
    "sql error",
    "pdoexception",
]
COMMON_DIRS = ["admin/", "backup/", "config/", "uploads/", "db/", "old/", ".git/", ".env", "test/"]
SKIP_EXT = (".jpg", ".png", ".gif", ".css", ".js", ".ico", ".woff", ".ttf")

# ---------------- HELPERS ----------------
def banner():
    print(Fore.CYAN + Style.BRIGHT + r"""
 __        __   _     ____                                      
 \ \      / /__| |__ | ___|__ _ __ ___  ___ _ __   ___ _ __ ___ 
  \ \ /\ / / _ \ '_ \| |_/ _ \ '__/ __|/ _ \ '_ \ / _ \ '__/ __|
   \ V  V /  __/ |_) |  _  __/ |  \__ \  __/ | | |  __/ |  \__ \
    \_/\_/ \___|_.__/|_| \___|_|  |___/\___|_| |_|\___|_|  |___/
    🕵️‍♂️  Modular Web Vulnerability Scanner with sqlmap option
""" + Style.RESET_ALL)


def get_page(session, url):
    try:
        return session.get(url, headers=HEADERS, timeout=TIMEOUT)
    except requests.RequestException:
        return None


def find_links(base, html):
    soup = BeautifulSoup(html, "lxml")
    links = set()
    for tag in soup.find_all("a", href=True):
        href = tag.get("href")
        if href.startswith(("mailto:", "javascript:")):
            continue
        full = urljoin(base, href)
        if any(full.lower().endswith(ext) for ext in SKIP_EXT):
            continue
        if full.startswith(base):
            links.add(full.split("#")[0])
    return links


# ---------------- VULN CHECKS ----------------
def extract_forms(html, base_url):
    """Extract all forms from HTML."""
    forms = []
    soup = BeautifulSoup(html, "lxml")
    for form in soup.find_all("form"):
        raw_action = form.get("action") or ""
        action = urljoin(base_url, raw_action)
        method = form.get("method", "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            typ = inp.get("type", "text")
            val = inp.get("value", "")
            if inp.name == "select":
                opt = inp.find("option")
                if opt and opt.get("value"):
                    val = opt.get("value")
            inputs.append({"name": name, "type": typ, "value": val})
        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms


def check_sql_injection(session, url, html=""):
    """Detect SQLi in GET + POST forms. Improved: checks HTTP 500s, broader error matching,
       extra payload shapes, and prints short debugging snippets for failing responses.
       Returns list of findings.
    """
    findings = []
    try:
        # Prefer already-fetched HTML if provided by caller
        r = None
        if not html:
            r = get_page(session, url)
            if not r:
                return findings
            html = r.text
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Normalize error patterns (loose, lowercased)
        ERR_PATTERNS = [e.lower() for e in SQL_ERRORS] + [
            "operationalerror", "sqlite3", "mysql", "psql", "traceback", "syntax error"
        ]

        # Quick scan for visible DB errors already present in page HTML
        page_low = (html or "").lower()
        for pat in ERR_PATTERNS:
            if pat in page_low:
                findings.append({
                    "url": url,
                    "type": "SQL Injection (Error-Based - page contains DB error)",
                    "evidence": pat,
                    "severity": "High",
                    "snippet": (html or "")[:500]
                })
                break

        # Additional payload shapes (a few common ones)
        enhanced_payloads = list(dict.fromkeys(SQLI_PAYLOADS + ["'--", "\"--", "' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE users; --","SLEEP(1)","SLEEP(2)","SLEEP(3)","SLEEP(4)","SLEEP(5)","SLEEP(10)"])) 

        # --- GET parameter SQLi ---
        if parsed.query:
            base, query = url.split("?", 1)
            params = query.split("&")
            for i, p in enumerate(params):
                key = p.split("=")[0]
                for payload in enhanced_payloads:
                    qcopy = params.copy()
                    qcopy[i] = f"{key}={requests.utils.requote_uri(payload)}"
                    test_url = base + "?" + "&".join(qcopy)
                    start = time.time()
                    resp = get_page(session, test_url)
                    elapsed = time.time() - start
                    if not resp:
                        continue

                    body_low = resp.text.lower()
                    # HTTP 500+ is a useful heuristic (server error / stack trace)
                    if resp.status_code >= 500:
                        findings.append({
                            "url": test_url,
                            "type": "SQL Injection (Server Error - GET)",
                            "evidence": f"HTTP {resp.status_code}",
                            "severity": "High",
                            "snippet": resp.text[:500]
                        })
                    else:
                        for pat in ERR_PATTERNS:
                            if pat in body_low:
                                findings.append({
                                    "url": test_url,
                                    "type": "SQL Injection (Error-Based - GET)",
                                    "evidence": pat,
                                    "payload": payload,
                                    "severity": "High",
                                    "snippet": resp.text[:500]
                                })
                                break

                    # time-based heuristic
                    if elapsed > 4:
                        findings.append({
                            "url": test_url,
                            "type": "SQL Injection (Time-Based - GET)",
                            "evidence": f"Delay {elapsed:.1f}s",
                            "payload": payload,
                            "severity": "High"
                        })

        # --- POST form SQLi ---
        forms = extract_forms(html, url)
        for form in forms:
            action = form["action"] or url
            method = form["method"]
            inputs = form["inputs"]
            has_password = any(inp["type"].lower() == "password" for inp in inputs)
            data = {inp["name"]: inp.get("value", "") for inp in inputs}

            if has_password:
                print(Fore.CYAN + f"[*] Detected login form at {action}. Testing SQLi payloads...")

            # try injecting into any non-hidden text-like inputs too
            injectable_names = [inp["name"] for inp in inputs if inp["type"].lower() not in ("hidden","submit","button")]
            if not injectable_names:
                injectable_names = [inp["name"] for inp in inputs]

            for payload in enhanced_payloads:
                test_data = data.copy()
                # inject payload into all candidate fields (aggressive) and also username-specific fields
                for name in injectable_names:
                    lname = name.lower()
                    if "user" in lname or "name" in lname or "email" in lname or not has_password:
                        test_data[name] = payload
                    if has_password and "pass" in lname:
                        test_data[name] = "password"

                try:
                    start = time.time()
                    if method == "post":
                        resp = session.post(action, data=test_data, headers=HEADERS, timeout=TIMEOUT)
                    else:
                        resp = session.get(action, params=test_data, headers=HEADERS, timeout=TIMEOUT)
                    elapsed = time.time() - start
                    if not resp:
                        continue

                    body_low = resp.text.lower()
                    # HTTP 500+ indicates server error / stack trace
                    if resp.status_code >= 500:
                        findings.append({
                            "url": action,
                            "type": "SQL Injection (Server Error - Form)",
                            "evidence": f"HTTP {resp.status_code}",
                            "payload": test_data,
                            "severity": "High",
                            "snippet": resp.text[:500]
                        })
                    else:
                        for pat in ERR_PATTERNS:
                            if pat in body_low:
                                findings.append({
                                    "url": action,
                                    "type": "SQL Injection (Error-Based - Form)",
                                    "evidence": pat,
                                    "payload": test_data,
                                    "severity": "High",
                                    "snippet": resp.text[:500]
                                })
                                break

                    # time-based
                    if elapsed > 4:
                        findings.append({
                            "url": action,
                            "type": "SQL Injection (Time-Based - Form)",
                            "evidence": f"Delay {elapsed:.1f}s",
                            "payload": test_data,
                            "severity": "High"
                        })

                except Exception as e:
                    # don't fail the whole scan; but log local debugging info if useful
                    print(Fore.YELLOW + f"[!] Post test failed for {action} with payload {payload}: {e}")
                    continue

    except Exception as e:
        print(Fore.RED + f"[!] SQLi check failed on {url}: {e}")
    return findings



def check_xss(session, url):
    """Detect reflected XSS. Returns list of findings."""
    findings = []
    parsed = urlparse(url)
    if not parsed.query:
        return findings
    base, query = url.split("?", 1)
    params = query.split("&")

    for i, param in enumerate(params):
        key = param.split("=")[0]
        for payload in XSS_PAYLOADS:
            qcopy = params.copy()
            qcopy[i] = f"{key}={payload}"
            test_url = base + "?" + "&".join(qcopy)
            r = get_page(session, test_url)
            if not r:
                continue
            if payload.lower() in r.text.lower():
                findings.append({
                    "url": test_url,
                    "type": "Reflected XSS",
                    "evidence": payload,
                    "severity": "High"
                })
                break
    return findings


def check_headers(resp, url):
    """Check for missing security headers."""
    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Referrer-Policy",
    ]
    missing = [h for h in required if h not in resp.headers]
    if missing:
        return {"url": url, "type": "Missing Headers", "evidence": ", ".join(missing), "severity": "Low"}
    return None


def dir_enum(session, base_url, wordlist=None):
    """Threaded directory enumeration using provided list or built-in commons."""
    dirs = wordlist if wordlist else COMMON_DIRS
    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = []
        for d in dirs:
            full = urljoin(base_url, d)
            futures.append(ex.submit(get_page, session, full))
        for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Dir Enum"):
            try:
                r = f.result()
                if r and r.status_code in (200, 403):
                    findings.append({
                        "url": r.url,
                        "type": "Sensitive Directory",
                        "evidence": f"Status {r.status_code}",
                        "severity": "Medium"
                    })
            except Exception:
                continue
    return findings


# ---------------- sqlmap integration ----------------
def run_sqlmap_on_target(sqlmap_bin, target_url, timeout=120, extra_args=None):
    """
    Run sqlmap as subprocess against target_url.
    Returns parsed result dict or None.
    """
    cmd = [sqlmap_bin, "-u", target_url, "--batch", "--level=2", "--risk=1", "--random-agent"]
    if extra_args:
        cmd += extra_args
    # run with a timeout
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = proc.stdout + "\n" + proc.stderr
        out_lower = out.lower()
        # crude detection of success in sqlmap output
        if "is vulnerable" in out_lower or "parameter" in out_lower and "is vulnerable" in out_lower:
            return {"url": target_url, "type": "SQL Injection (sqlmap)", "evidence": "sqlmap detected vulnerability", "raw": out}
        # sometimes sqlmap prints "no injection point was found"
        if "no injection point was found" in out_lower or "all tested parameters do not appear to be injectable" in out_lower:
            return None
        # if sqlmap found payloads or evidence strings (heuristic)
        if "payload" in out_lower or "web application" in out_lower and "vulnerable" in out_lower:
            return {"url": target_url, "type": "SQL Injection (sqlmap - heuristic)", "evidence": "sqlmap output", "raw": out}
        return None
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + f"[!] sqlmap timed out for {target_url} (timeout {timeout}s)")
        return None
    except FileNotFoundError:
        print(Fore.RED + "[!] sqlmap binary not found. Install sqlmap or pass --sqlmap-bin with path.")
        return None
    except Exception as e:
        print(Fore.RED + f"[!] sqlmap run error for {target_url}: {e}")
        return None


# ---------------- CRAWLER ----------------
def crawl(session, start_url, depth):
    visited = set()
    # normalize start_url to path-only base for same-domain checks
    parsed_start = urlparse(start_url)
    base_root = f"{parsed_start.scheme}://{parsed_start.netloc}"
    to_visit = {start_url}
    all_links = set()
    for d in range(depth):
        new_links = set()
        for url in tqdm(to_visit, desc=f"Crawling depth {d+1}"):
            if url in visited:
                continue
            visited.add(url)
            resp = get_page(session, url)
            if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            links = find_links(base_root, resp.text)
            new_links.update(links)
            all_links.update(links)
        to_visit = new_links - visited
    return all_links


# ---------------- SCANNER CORE ----------------
def scan_page(session, url, mode, use_sqlmap=False, sqlmap_bin="sqlmap", sqlmap_timeout=120):
    findings = []
    r = get_page(session, url)
    if not r:
        return findings
    html = r.text

    if mode in ("all", "sqli"):
        findings.extend(check_sql_injection(session, url, html))
    if mode in ("all", "xss"):
        findings.extend(check_xss(session, url))
    if mode in ("all", "headers"):
        hdr = check_headers(r, url)
        if hdr:
            findings.append(hdr)

    # optionally run sqlmap on any GET urls with params or form actions where we already have a finding candidate
    if use_sqlmap and mode in ("all", "sqli"):
        # candidate targets to run sqlmap on: URL (if it has params) and any forms' action
        candidates = set()
        parsed = urlparse(url)
        if parsed.query:
            candidates.add(url)
        # extract form actions
        forms = extract_forms(html, url)
        for f in forms:
            # run sqlmap only on http(s) actions
            if f["action"].startswith("http"):
                candidates.add(f["action"])
            else:
                # resolve relative
                candidates.add(urljoin(url, f["action"]))
        # run sqlmap sequentially (or you can parallelize if you want)
        for tgt in candidates:
            res = run_sqlmap_on_target(sqlmap_bin, tgt, timeout=sqlmap_timeout)
            if res:
                findings.append({**res, "severity": "High"})
    return findings


def run_scanner(base_url, depth=2, mode="all", wordlist=None, use_sqlmap=False, sqlmap_bin="sqlmap", sqlmap_timeout=120):
    session = requests.Session()
    results = []
    print(Fore.YELLOW + f"[+] Crawling {base_url} (depth={depth})")
    urls = crawl(session, base_url, depth)
    # also include the base_url itself for testing (crawler returns links discovered)
    urls.add(base_url)
    print(Fore.GREEN + f"[+] Found {len(urls)} pages (including seed)")

    print(Fore.YELLOW + f"[+] Running mode: {mode.upper()} (sqlmap {'ON' if use_sqlmap else 'OFF'})")

    # scan pages in threadpool
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = []
        for url in urls:
            futures.append(ex.submit(scan_page, session, url, mode, use_sqlmap, sqlmap_bin, sqlmap_timeout))
        for f in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Scanning pages"):
            try:
                res = f.result()
                if res:
                    results.extend(res)
            except Exception:
                continue

    # directory enumeration
    if mode in ("all", "dirs"):
        results.extend(dir_enum(session, base_url, wordlist))

    return results


# ---------------- REPORT ----------------
def save_report(results, out):
    # dedupe results by url+type+evidence (simple)
    seen = set()
    deduped = []
    for r in results:
        key = (r.get("url"), r.get("type"), str(r.get("evidence")))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(r)

    for r in deduped:
        color = Fore.RED if r.get("severity") == "High" else Fore.YELLOW if r.get("severity") == "Medium" else Fore.CYAN
        print(color + f"[{r.get('severity')}] {r.get('type')} → {r.get('url')}")
        if "payload" in r:
            print(Fore.MAGENTA + f"    payload: {r['payload']}")
        if "raw" in r:
            # avoid printing very long sqlmap output; print short snippet
            raw_snippet = r["raw"][:1000].strip().replace("\n", " ")
            print(Fore.WHITE + f"    sqlmap: {raw_snippet}...")

    if out:
        with open(out, "w", encoding="utf-8") as f:
            lines = []
            for r in deduped:
                lines.append(f"[{r.get('severity')}] {r.get('type')} → {r.get('url')} ({r.get('evidence')})")
                if "payload" in r:
                    lines.append(f"    payload: {r['payload']}")
            f.write("\n".join(lines))
        print(Fore.GREEN + f"[+] Report saved to {out}")

    with open("report.json", "w", encoding="utf-8") as f:
        json.dump(deduped, f, indent=2)
    print(Fore.GREEN + "[+] JSON report written to report.json")


# ---------------- MAIN ----------------
def main():
    banner()
    parser = argparse.ArgumentParser(description="Advanced Modular Web Vulnerability Scanner (sqlmap optional)")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g., http://127.0.0.1:5000/)")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Crawl depth (default=2)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for directory enumeration")
    parser.add_argument("-m", "--mode", choices=["all", "sqli", "xss", "headers", "dirs"], default="all",
                        help="Select scan mode (default: all)")
    parser.add_argument("-o", "--output", help="Save human-readable text report to file")
    parser.add_argument("--use-sqlmap", action="store_true", help="Run sqlmap for targets (requires sqlmap installed)")
    parser.add_argument("--sqlmap-bin", default="sqlmap", help="Path to sqlmap binary (default: sqlmap)")
    parser.add_argument("--sqlmap-timeout", type=int, default=120, help="Timeout seconds for sqlmap run per target")
    args = parser.parse_args()

    wordlist = None
    if args.wordlist and os.path.isfile(args.wordlist):
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            wordlist = [ln.strip() for ln in f if ln.strip()]

    results = run_scanner(args.url, args.depth, args.mode, wordlist, use_sqlmap=args.use_sqlmap,
                          sqlmap_bin=args.sqlmap_bin, sqlmap_timeout=args.sqlmap_timeout)
    save_report(results, args.output)


if __name__ == "__main__":
    main()
