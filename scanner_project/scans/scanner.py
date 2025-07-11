import nmap
import requests

def run_nmap_scan(target):
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-p- --open')
        open_ports = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                open_ports.extend(str(port) for port in ports)
        return open_ports
    except Exception as e:
        print(f"[Nmap Error] {e}")
        return []

def check_sql_injection(target):
    try:
        payload = "' OR '1'='1"
        response = requests.get(target, params={"id": payload}, timeout=10)
        if "sql" in response.text.lower() or "syntax" in response.text.lower():
            return True
    except Exception as e:
        print(f"[SQLi Check Error] {e}")
    return False

def check_xss(target):
    try:
        payload = "<script>alert(1)</script>"
        response = requests.get(target, params={"q": payload}, timeout=10)
        if payload in response.text:
            return True
    except Exception as e:
        print(f"[XSS Check Error] {e}")
    return False

def check_directory_listing(target):
    try:
        if not target.endswith('/'):
            target += '/'
        response = requests.get(target, timeout=10)
        return "Index of /" in response.text
    except Exception as e:
        print(f"[Directory Listing Check Error] {e}")
    return False

def check_clickjacking(target):
    try:
        response = requests.get(target, timeout=10)
        if 'X-Frame-Options' not in response.headers:
            return True
    except Exception as e:
        print(f"[Clickjacking Check Error] {e}")
    return False

def run_full_scan(target):
    print(f"[run_full_scan] Running scan for {target}")
    results = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "safe": True,
        "details": {}
    }

    open_ports = run_nmap_scan(target)
    print(f"[run_full_scan] Open ports: {open_ports}")
    if open_ports:
        results["high"] += len(open_ports)
        results["details"]["open_ports"] = open_ports
        results["safe"] = False

    if check_sql_injection(target):
        print(f"[run_full_scan] SQL Injection found!")
        results["critical"] += 1
        results["details"]["sql_injection"] = True
        results["safe"] = False

    if check_xss(target):
        print(f"[run_full_scan] XSS vulnerability found!")
        results["medium"] += 1
        results["details"]["xss"] = True
        results["safe"] = False

    if check_directory_listing(target):
        print(f"[run_full_scan] Directory listing enabled!")
        results["low"] += 1
        results["details"]["dir_listing"] = True
        results["safe"] = False

    if check_clickjacking(target):
        print(f"[run_full_scan] Clickjacking possible!")
        results["info"] += 1
        results["details"]["clickjacking"] = True
        results["safe"] = False

    if results["safe"]:
        print(f"[run_full_scan] No vulnerabilities found. Site is safe.")
        results["details"]["message"] = "Уязвимостей не обнаружено. Сайт выглядит безопасным."

    return results

