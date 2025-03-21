"""
module that receivers packets and sends acks to the sender
"""
import argparse
import time
import socket
import rdt


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
send_port = 9000
net_port = 9050
rcv_port = 9090
s.bind(('127.0.0.1', rcv_port))
net_addr = ('127.0.0.1', net_port)
excepted_seq = 0
buffer = {}
rcvd_packets =[]


def main():
    """
    main function that listens for packets from the network, and sends back acks
    """
    global excepted_seq
    while 1:
        pkt, _ = s.recvfrom(rdt.max_pkt_size + 30)
        src, dst, length, chksum, seq, ack, data = pkt.decode().split('/')
        # print(data)
        
        if rdt.checksum(data) != int(chksum):
            print(f'checksum incorrect for packet {seq}')
            continue
        else:
            rcvd_packets.append(pkt)

        # correct seq
        if int(seq) == excepted_seq:
            print(f'got packet {seq}')
            excepted_seq += 1

            # check for buffered packets
            while excepted_seq in buffer:
                data = buffer.pop(excepted_seq)
                print(f'got packet {excepted_seq}')
                excepted_seq += 1

        # ahead of expected, add to buffer
        elif int(seq) > excepted_seq:
            print(f'expected {excepted_seq}, got {seq}')
            buffer[int(seq)] = data

        # behind expected, send ack
        else:
            ack = rdt.create_pkt(rcv_port, net_port, seq, 1, '')
            s.sendto(ack, net_addr)
            print(f'sent ack {seq}')
        
        # send cum ack to last packet received
        ack_num = max(0, excepted_seq - 1)
        ack = rdt.create_pkt(rcv_port, net_port, ack_num, 1, '')
        s.sendto(ack, net_addr)
        print(f'sent ack {ack_num}')


if __name__ == '__main__':
    main()
