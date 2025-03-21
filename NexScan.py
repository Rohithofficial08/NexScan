import requests
from bs4 import BeautifulSoup
import argparse
import subprocess
import socket
import re

def get_ip(url):
    """Resolve the IP address of the target."""
    domain = url.replace("http://", "").replace("https://", "").split("/")[0]
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip}")
        return ip
    except socket.gaierror:
        print("[!] Could not resolve IP address.")
        return None

def run_whatweb(url):
    """Run WhatWeb to gather information about the target."""
    print("\n[*] Running WhatWeb...")
    try:
        result = subprocess.check_output(["whatweb", url], text=True)
        print(result)
    except FileNotFoundError:
        print("[!] WhatWeb not found. Install it using: sudo apt install whatweb")
    except subprocess.CalledProcessError as e:
        print(f"[!] Error running WhatWeb: {e}")

def run_nmap(ip):
    """Run Nmap with the vulners script and extract CVEs."""
    if ip:
        print("\n[*] Running Nmap Vulnerability Scan...")
        try:
            ports = "80,443,20,21,22,23,25,8080"
            result = subprocess.check_output(["nmap", "-sV", "--script", "vulners", "-p", ports, ip], text=True)
            print(result)
            
            # Extract and display CVEs separately
            cves = set(re.findall(r'CVE-\d{4}-\d+', result))
            if cves:
                print("\n[*] CVEs Found:")
                for cve in sorted(cves):
                    print(f" - {cve}")
            else:
                print("\n[*] No CVEs found.")
        except FileNotFoundError:
            print("[!] Nmap not found. Install it using: sudo apt install nmap")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error running Nmap: {e}")

def check_security_headers(url):
    """Check for missing security headers."""
    headers = [
        "X-Frame-Options", "X-XSS-Protection", "Strict-Transport-Security", "Content-Security-Policy",
        "Referrer-Policy", "Permissions-Policy", "Expect-CT", "Feature-Policy", "X-Content-Type-Options"
    ]
    
    try:
        response = requests.get(url, timeout=5)
        print(f"\n[*] Scanning: {url}\n")
        for header in headers:
            if header in response.headers:
                print(f"[+] {header}: {response.headers[header]}")
            else:
                print(f"[-] {header} is missing!")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")

def check_outdated_software(url):
    """Detect outdated server software."""
    try:
        response = requests.get(url, timeout=5)
        server_header = response.headers.get("Server")
        if server_header:
            print(f"\n[+] Server: {server_header}")
            if "Apache/2.2" in server_header or "nginx/1.14" in server_header:
                print("[!] Warning: Server may be outdated! Consider updating to a newer version.")
        else:
            print("[-] Server header not found.")
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")

def main():
    parser = argparse.ArgumentParser(description="Advanced Vulnerability Scanner")
    parser.add_argument("url", nargs="?", help="Target website URL")
    parser.add_argument("-i", "--ip", help="Target IP address")
    args = parser.parse_args()
    
    if args.ip:
        run_nmap(args.ip)
    elif args.url:
        run_whatweb(args.url)
        ip = get_ip(args.url)
        if ip:
            run_nmap(ip)
        check_security_headers(args.url)
        check_outdated_software(args.url)
    else:
        print("[!] Please provide a URL or an IP address.")
    
if __name__ == "__main__":
    main()

