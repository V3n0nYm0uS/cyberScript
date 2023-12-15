#!/usr/bin/env python3
import argparse
from scapy.all import sniff, Raw
from scapy.layers import http

def main():
    ecouteReseau()

def ecouteReseau():
    sniff(iface=args.iface, filter=args.filter, count=args.count, prn=analysePaquet, store=args.save)

def analysePaquet(paquet):
    if paquet.haslayer(http.HTTPRequest) and paquet[http.HTTPRequest].haslayer(http.HTTPRequest):
        extractUrl(paquet)
        extractIds(paquet)

def extractUrl(paquet):
    url = paquet[http.HTTPRequest].Host.decode() + paquet[http.HTTPRequest].Path.decode()
    print(f"URL extracted: {url}", url)

# You should change this list to something bigger
keywords_to_search = ('username', 'uname', 'user', 'login', 'password', 'pass', 'signin', 'signup', 'name')

def extractIds(paquet):
    if paquet[http.HTTPRequest].haslayer(Raw):
        body = paquet[http.HTTPRequest].Raw.load.decode(errors="ignore")
        for keyword in keywords_to_search:
            if keyword in body:
                print(f"Keyword '{keyword}' found in the request body.")

    params = paquet[http.HTTPRequest].http_request
    for keyword in keywords_to_search:
        if keyword in params:
            print(f"Keyword '{keyword}' found in the request parameters.")
    



if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Sniffer Python",
        description="Sniff the network",
        epilog="Do not use this program for malicious activity it's written only for educational purposes."
    )
    parser.add_argument("-f", "--filter")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("iface")
    parser.add_argument("-c", "--count")
    parser.add_argument("-s", "--save", action="store_true")
    args = parser.parse_args()
    main()