import argparse
import time
import socket
import scapy.all as scapy


def send_pkt(data, dest, seq):
    dest_ip = socket.gethostbyname(dest)
    
    pkt = scapy.IP(dst=dest_ip) / seq / scapy.UDP() / data
    
    start_time = time.time()
    return pkt, start_time


def corrupt(pkt):
    csum = 0x0
    for b in scapy.raw(pkt[scapy.UDP]):
        csum += b

    if pkt[scapy.UDP].chksum + csum == 0xFFFF:
        return False
    return True


def recieve_pkt(pkt, seq):
    if corrupt(pkt) or pkt.seq != seq:
        send_pkt(pkt)
    elif not corrupt(pkt) and pkt.seq == seq:
        return True


def forward_pkt(pkt, new_dest):
    new_dest_ip = socket.gethostbyname(new_dest)
    pkt.dst = new_dest_ip

    return pkt


def main():
    return


if __name__ == '__main__':
    main()