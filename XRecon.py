#!/usr/bin/env python3
import os
import argparse
import socket
import whois
import requests

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

Creator : 0xMiawChan - XRecon 0.1 Version
    """)

def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"[+] IP Address: {ip}")
    except:
        print("[-] Failed to get IP address.")

def whois_lookup(domain):
    try:
        info = whois.whois(domain)
        print(f"[+] WHOIS Info:\n{info}")
    except:
        print("[-] WHOIS lookup failed.")

def headers_lookup(url):
    try:
        r = requests.get(url)
        print(f"[+] Headers for {url}:\n{r.headers}")
    except:
        print("[-] Failed to retrieve headers.")

if __name__ == "__main__":
    banner()

    parser = argparse.ArgumentParser(description="ShadowRecon - Simple Recon Tool")
    parser.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--whois", action="store_true", help="Perform WHOIS lookup")
    parser.add_argument("--ip", action="store_true", help="Get IP address")
    parser.add_argument("--headers", action="store_true", help="Get HTTP headers")

    args = parser.parse_args()

    if args.domain:
        if args.ip:
            get_ip(args.domain)
        if args.whois:
            whois_lookup(args.domain)
        if args.headers:
            headers_lookup(f"http://{args.domain}")
    else: