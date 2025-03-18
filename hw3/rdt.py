import argparse
import time
import socket
import scapy.all as scapy



def send_pkt(data, dest, seq):
    dest_ip = socket.gethostbyname(dest)

    pkt = scapy.IP(dst=dest_ip) / seq / scapy.UDP() / data
    

    reply = scapy.sr1(pkt, verbose=0)
    return


def recieve_pkt(pkt):


    return


def forward_pkt():
    return


def main():
    return


if __name__ == '__main__':
    main()