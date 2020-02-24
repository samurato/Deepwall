#!/usr/bin/python
from scapy.all import *

def pkt_callback(pkt):
    pkt.show() # debug statement
    print("-------------------new Packet --------------------------------")

#sniff(iface="ens33", prn=pkt_callback, filter="tcp", store=0)

def pkt_tcp(pkt):
    print(pkt)
sniff(iface="ens33", prn=pkt_callback, filter="tcp", store=0)