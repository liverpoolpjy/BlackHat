# -*- coding: utf-8 -*-
from scapy.all import srp, Ether, ARP, conf
lan = '192.168.1.0/24'
ip = '192.168.1.111'
conf.verb = 0
ans, unans = srp(Ether(dst="FF:FF:FF:FF:FF:FF")/ARP(pdst=lan), timeout=2)
for snd, rcv in ans:
    cur_mac = rcv.sprintf("%Ether.src%")
    cur_ip = rcv.sprintf("%ARP.psrc%")
    print cur_mac + ' - ' +cur_ip