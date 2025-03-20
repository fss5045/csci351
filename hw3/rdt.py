import argparse
import time
import socket
import scapy.all as scapy


def checksum(data):
    csum = 0x0
    for b in data.encode():
        csum += b
    
    csum = csum ^ 0xFFFF
    return csum


def create_pkt(dst, src, seq, ack, data):
    length = len(data) + 48
    chksum = checksum(data)
    pkt = f'{src}/{dst}/{length}/{chksum}/{seq}/{ack}/{data}'
    print(pkt)
    return pkt.encode()


def send_pkt(pkt, dst, sock):
    start_time = time.time()
    sock.sendto(pkt)
    return start_time


def is_corrupt(pkt):
    csum = checksum(scapy.raw(pkt))
    if pkt[scapy.UDP].chksum == csum:
        return False
    return True


def recieve_pkt(pkt, seq):
    if is_corrupt(pkt) or pkt.seq != seq:
        send_pkt(pkt)
    elif not is_corrupt(pkt) and pkt.seq == seq:
        return True


def forward_pkt(pkt, new_dest):
    new_dest_ip = socket.gethostbyname(new_dest)
    pkt.dst = new_dest_ip
    
    return pkt


def main():
    
    # create_pkt('hibro', 'google.com', 3, 9000, 9090, 0)
    return


if __name__ == '__main__':
    main()