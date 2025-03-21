"""
module that sends packets with data
"""
import argparse
import time
import socket
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
base = 0
next_seq = 0
packets = []
acked_packets = {}
timestamp = {}


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
    main function that arg parses, splits the data into packets, 
    and then sends the packets through a defined port to the netwrork
    """
    global next_seq
    parser = argparse.ArgumentParser()
    parser.add_argument('-d')
    parser.add_argument('-s', type=int, default=rdt.max_pkt_size)
    args = parser.parse_args()

    # check args
    if args.d:
        data = args.d
    else:
        data = 'default_packet_data'

    if args.s > rdt.max_pkt_size:
        print(f'packet size must be below {rdt.max_pkt_size}')
        args.s = rdt.max_pkt_size

    # create packets from data
    while data:
        pkt_data = data[:args.s]
        data = data[args.s:]
        pkt = rdt.create_pkt(send_port, rcv_port, next_seq, 0, pkt_data)
        packets.append(pkt)
        next_seq += 1

    wt = Thread(target=wait_for_ack, daemon=True)
    wt.start()

    next_seq = 0
    while base < len(packets):
        # send packets in window
        print(base, next_seq)
        with lock:
            while next_seq < (base + windowsize) and next_seq < len(packets):
                print(f'sending packet {next_seq}')
                s.sendto(packets[next_seq], rcv_addr)
                timestamp[next_seq] = time.time()
                next_seq += 1
        
        # check acks
        with lock:
            curr_time = time.time()
            for i in range(base, min(base + windowsize, len(packets))):
                # print(curr_time - timestamp.get(i, 0))
                if i not in acked_packets and (curr_time - timestamp.get(i, 0)) > timeout:
                    print(f'resending packet {i}')
                    s.sendto(packets[i], rcv_addr)
        
        time.sleep(wait)

    print('all packets sent and acked')

    wt.join()

if __name__ == '__main__':
    main()
