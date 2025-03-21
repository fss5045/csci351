import argparse
import time
import socket
import random
import scapy.all as scapy
import rdt

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
send_port = 9000
net_port = 9050
rcv_port = 9090
s.bind(('127.0.0.1', net_port))
excepted_seq = 0


def drop():
    drop_p = random.random()
    if drop_p < 0.2:
        return True
    return False


def corrupt(pkt):
    corrupt_p = random.random()
    if corrupt_p < 0.2:
        info = pkt.decode().split('/')
        info[-1] = 'bad'
        return '/'.join(info).encode()
    return False


def main():
    while 1:
        pkt, _ = s.recvfrom(rdt.max_pkt_size + 25)
        src, dst, length, chksum, seq, ack, data = pkt.decode().split('/')

        # set destination based on source
        if int(src) == send_port:
            print(f'got packet {seq} from sender')
            addr = ('127.0.0.1', rcv_port)
        elif int(src) == rcv_port:
            print(f'got ack {seq} from receiver')
            addr = ('127.0.0.1', send_port)
        
        # drop
        if drop():
            print(f'dropping packet {seq}')
            continue

        # corrupt
        cpkt = corrupt(pkt)
        if cpkt:
            print(f'forwarding corrupt packet {seq}')
            s.sendto(cpkt, addr)
        # normal operation
        else:
            print(f'forwaring packet {seq}')
            s.sendto(pkt, addr)


if __name__ == '__main__':
    main()
    