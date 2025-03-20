import argparse
import time
import socket
import scapy.all as scapy
from threading import *
import rdt

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
send_port = 9000
rcv_port = 9050
s.bind(('127.0.0.1', send_port))
rcv_addr = ('127.0.0.1', rcv_port)
lock = Lock()
windowsize = 3
timeout = 5
wait = 5
max_pkt_size = 5
seq = 0
next_seq = windowsize
packets = []
sent_packets = []


def wait_for_ack():
    while 1:
        lock.acquire()
        pkt = s.recvfrom(max_pkt_size)
        info = pkt.decode().split('/')
        if info[-2] == 1 and info[-3] == next_seq:
            seq += 1
            next_seq += 1
            lock.release()
            

parser = argparse.ArgumentParser()
parser.add_argument('-d')
parser.add_argument('-s', type=int, default=max_pkt_size)
args = parser.parse_args()

if args.d:
    data = args.d
else:
    data = 'default_packet_data'
if args.s > max_pkt_size:
    print(f'packet size must be below {max_pkt_size}')
    args.s = max_pkt_size


# create packets from data
run = True
while run:
    if len(data) > args.s:
        pkt_data = data[:args.s]
        data = data[args.s:]
    else:
        pkt_data = data
        run = False

    pkt = rdt.create_pkt(send_port, rcv_port, seq, 0, pkt_data)
    packets.append(pkt)

wt = Thread(target=wait_for_ack)
wt.start()

while 1:
    # start_time = time.time()
    # send packets in the window
    print(seq, next_seq)
    if next_seq == len(packets):
        break
    windowpkts = packets[seq:next_seq]
    for pkt in windowpkts:
        # s.sendto(pkt, rcv_addr)
        sent_packets.append(pkt)
        time.sleep(wait)
        print(sent_packets)
        seq += 1
        next_seq += 1

wt.join()