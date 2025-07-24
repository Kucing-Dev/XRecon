#!/usr/bin/env python3
import os
import argparse
import socket
import whois
import requests
import json

def banner():
    print(r"""
    ) (
 ( /( )\ )
 )\()|()/(  (
((_)\ /(_))))\ (  (   (
__((_|_)) /((_))\ )\  )\ )
\ \/ / _ (_)) ((_|(_)_(_/(
 >  <|   / -_) _/ _ \ ' \))
/_/\_\_|_\___\__\___/_||_|


Creator : 0xMiawChan - XRecon V 0.2
    """)

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip}")
        return ip
    except Exception as e:
        print(f"[-] Failed to get IP address: {e}")

def whois_lookup(domain):
    try:
        info = whois.whois(domain)
        print("[+] WHOIS Info:")
        print(info)
        return str(info)
    except Exception as e:
        print(f"[-] WHOIS lookup failed: {e}")

def headers_lookup(url):
    try:
        r = requests.get(url, headers={"User-Agent": "XRecon"})
        print(f"[+] Headers for {url}:\n")
        for k, v in r.headers.items():
            print(f"{k}: {v}")
        return r.headers
    except Exception as e:
        print(f"[-] Failed to retrieve headers: {e}")

def subdomain_lookup(domain):
    try:
        print(f"[+] Searching subdomains using crt.sh for {domain} ...")
        r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json")
        if r.status_code != 200:
            print("[-] Failed to retrieve subdomains.")
            return []
        data = r.json()
        subdomains = sorted(set(entry['name_value'] for entry in data))
        print("[+] Subdomains found:")
        for sub in subdomains:
            print(" -", sub)
        return subdomains
    except Exception as e:
        print(f"[-] Subdomain enumeration failed: {e}")
        return []

def port_scan(domain, ports=[80, 443, 21, 22, 25, 3306]):
    print(f"[+] Scanning ports on {domain} ...")
    open_ports = []
    try:
        ip = socket.gethostbyname(domain)
        for port in ports:
            s = socket.socket()
            s.settimeout(1)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f" - Open: {port}")
                open_ports.append(port)
            s.close()
        return open_ports
    except Exception as e:
        print(f"[-] Port scan failed: {e}")
        return []

def save_report(data, filename="report.json"):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4)
        print(f"[+] Report saved to {filename}")
    except Exception as e:
        print(f"[-] Failed to save report: {e}")

if __name__ == "__main__":
    banner()

    parser = argparse.ArgumentParser(description="XRecon - Simple Recon Tool")
    parser.add_argument("-d", "--domain", help="Target domain (e.g. example.com)", required=True)
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--ip", action="store_true", help="Get IP address")
    parser.add_argument("--headers", action="store_true", help="Get HTTP headers")
    parser.add_argument("--subdomains", action="store_true", help="Find subdomains via crt.sh")
    parser.add_argument("--ports", action="store_true", help="Scan common ports")
    parser.add_argument("--https", action="store_true", help="Use HTTPS instead of HTTP")
    parser.add_argument("--output", help="Save results to JSON file")

    args = parser.parse_args()
    result = {"domain": args.domain}

    if args.ip:
        result['ip'] = get_ip(args.domain)

    if args.whois:
        result['whois'] = whois_lookup(args.domain)

    if args.headers:
        proto = "https" if args.https else "http"
        result['headers'] = dict(headers_lookup(f"{proto}://{args.domain}"))

    if args.subdomains:
        result['subdomains'] = subdomain_lookup(args.domain)

    if args.ports:
        result['open_ports'] = port_scan(args.domain)

    if args.output:
        save_report(result, args.output)
