"""
module that sends a file to a server
"""
import argparse
import time
import socket
import random
from threading import *
import rdt
import sender


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_port = 8000
client_port = 8050
s.bind(('127.0.0.1', client_port))
server_addr = ('127.0.0.1', server_port)
lock = Lock()
windowsize = 3
timeout = 5
wait = 5
base = 0
next_seq = 0
packets = []
acked_packets = {}
timestamp = {}


def read_flle(path):
    """
    reads in a file and splits it into packets
    path: filepath to read in
    """
    global next_seq
    with open(path, 'r') as file:
        data = file.read()
    
    data += "EOF"
    while data:
        pkt_data = data[:rdt.max_pkt_size]
        data = data[rdt.max_pkt_size:]
        pkt = rdt.create_pkt(client_port, server_port, next_seq, 0, pkt_data)
        packets.append(pkt)
        next_seq += 1


def wait_for_ack():
    """
    runs on a separate thread and listens for ack response packets,
    increases the base of the window for sending packets
    """
    global base
    while len(acked_packets) < len(packets):
        # print('waiting for ack')
        try:
            pkt, _ = s.recvfrom(rdt.max_pkt_size + 25)
            src, dst, length, chksum, seq, ack, data = pkt.decode().split('/')
            print(f'got packet {seq}: {ack}')
            if int(ack) == 1:
                with lock:
                    if int(seq) >= base:
                        acked_packets[int(seq)] = True
                        while base in acked_packets and acked_packets[base]:
                            base += 1
        except:
            break


def main():
    """
    main function that parses file argumnet and sends the file packets to the server
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('file')
    args = parser.parse_args()
    read_flle(args.file)

    wt = Thread(target=wait_for_ack, daemon=True)
    wt.start()

    next_seq = 0
    while base < len(packets):
        # send packets in window
        print(base, next_seq)
        with lock:
            while next_seq < (base + windowsize) and next_seq < len(packets):
                print(f'sending packet {next_seq}')
                s.sendto(packets[next_seq], server_addr)
                timestamp[next_seq] = time.time()
                next_seq += 1
        
        # check acks
        with lock:
            curr_time = time.time()
            for i in range(base, min(base + windowsize, len(packets))):
                # print(curr_time - timestamp.get(i, 0))
                if i not in acked_packets and (curr_time - timestamp.get(i, 0)) > timeout:
                    print(f'resending packet {i}')
                    s.sendto(packets[i], server_addr)
        
        time.sleep(wait)

    print('all packets sent and acked')

    wt.join()

if __name__ == '__main__':
    main()
