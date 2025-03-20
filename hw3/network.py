import argparse
import time
import socket
import random
import scapy.all as scapy
import rdt

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
send_port = 9050
rcv_port = 9090
s.bind(('127.0.0.1', send_port))
rcv_addr = ('127.0.0.1', rcv_port)
max_pkt_size = 5


def drop(pkt):
    drop_p = random.random()
    if drop_p < 0.2:
        return True
    return False


def corrupt(pkt):
    corrupt_p = random.random()
    if corrupt_p < 0.2:
        info = pkt.decode().split('/')
        info[-1] = 'corrupted'
        return '/'.join(info).encode()
    return False


def main():
    while 1:
        pkt = s.recvfrom(max_pkt_size)
        if drop(pkt):
            continue
        cpkt = corrupt(pkt)
        if cpkt:
            s.sendto(cpkt, rcv_addr)
        else:
            s.sendto(pkt, rcv_addr)
    