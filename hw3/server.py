"""
module that listens for file packets and writes to a file
"""
import time
import socket
import random
import rdt


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_port = 8000
client_port = 8050
s.bind(('127.0.0.1', server_port))
client_addr = ('127.0.0.1', client_port)
excepted_seq = 0
buffer = {}
rcvd_packets =[]


def write_to_file(name, data):
    """
    writes some data to file
    name: file to write to
    data: data to write in file

    """
    print('writing to file')
    with open(f'{name}.txt', 'a') as file:
        for d in data:
            file.write(d)


def main():
    """
    main function that listens for file packets and sends acks
    """
    global excepted_seq, rcvd_packets, buffer
    while 1:
        pkt, _ = s.recvfrom(rdt.max_pkt_size + 30)
        src, dst, length, chksum, seq, ack, data = pkt.decode().split('/')
        print(data)
        if data == "EOF":
            write_to_file('server_file', rcvd_packets)
            excepted_seq = 0
            buffer = {}
            rcvd_packets = []
            ack = rdt.create_pkt(server_port, client_port, seq, 1, '')
            s.sendto(ack, client_addr)
            print(f'sent ack {seq}')
            continue
        
        if rdt.checksum(data) != int(chksum):
            print(f'checksum incorrect for packet {seq}')
            continue
        else:
            rcvd_packets.append(data)

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
            ack = rdt.create_pkt(server_port, client_port, seq, 1, '')
            s.sendto(ack, client_addr)
            print(f'sent ack {seq}')
        
        # send cum ack to last packet received
        ack_num = max(0, excepted_seq - 1)
        ack = rdt.create_pkt(server_port, client_port, ack_num, 1, '')
        s.sendto(ack, client_addr)
        print(f'sent ack {ack_num}')


if __name__ == '__main__':
    main()
