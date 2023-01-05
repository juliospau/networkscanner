#!/bin/python3

from scapy.all import *
import argparse
import os

if os.geteuid() != 0:
    print ("¡EJECUTA COMO ROOT!".center(100, "="))
    exit()
else:
    pass

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", dest="target", help="IP o rango a escanear. Ejemplo: ./networkScan.py -t 10.0.2.1/24")
options = parser.parse_args()

def scan(ip):
    arp_request = ARP(pdst=ip) # Petición ARP
    broadcast = Ether(dst='FF:FF:FF:FF:FF:FF')  # MAC BROADCAST

    arp_request_broadcast = broadcast/arp_request
    
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # Se envía la petición ARP a la dirección MAC de broadcast

    print ( "IP".center(44), "MAC\n" )
    for i in answered_list:
        print ( '\t\t', i[1].psrc, "\t\t", i[1].src )

scan(options.target)
