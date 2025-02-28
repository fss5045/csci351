"""ping implementation"""
import argparse
import time
import socket
import scapy.all as scapy


def send_packet(size, dest, p_count):
    """creates and sends an icmp echo packet
    size: size in bytes of the icmp data bytes
    dest: ping destination
    p_count: # of packets sent, used for icmp seq
    returns: rtt if successful, 0 if time out, -1 if unknwon host name"""
    try:
        dest_ip = socket.gethostbyname(dest)
        pkt = scapy.IP(dst=dest_ip) / scapy.ICMP(seq=p_count+1) / bytes(range(size))
        start_time = time.time()
        reply = scapy.sr1(pkt, verbose=0)
        end_time = time.time()
        rtt = (end_time - start_time) * 1000

        if reply:
            linux_len = len(reply[scapy.ICMP].payload) + 8
            print (f'{linux_len} bytes from {reply.src}: time={rtt:.2f}ms ttl={reply.ttl} icmp_seq={reply[scapy.ICMP].seq}')
            return rtt

        print('Request timed out')
        return 0
    except:
        print('Unknown host name')
        return -1


def main():
    """main function, parses args and runs main loop"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--count', type=int)
    parser.add_argument('-i', '--wait', type=int, default=1)
    parser.add_argument('-s', '--packetsize', type=int, default=56)
    parser.add_argument('-t', '--timeout', type=int)
    parser.add_argument('dest')
    args = parser.parse_args()

    print(f'PING {args.dest} with {args.packetsize}({args.packetsize+28}) bytes of data')
    retval = 0
    packet_count = 0
    received = 0
    rtts = []
    start_time = time.time()
    try:
        while True:
            current_time = time.time()
            if args.timeout and current_time - start_time >= args.timeout:
                if args.count and packet_count < args.count:
                    retval = 1
                raise Exception('timed out')
            if args.count and packet_count >= args.count:
                raise Exception('count exceeded')
            rtt = send_packet(args.packetsize, args.dest, packet_count)
            if rtt == -1:
                return 2
            if rtt:
                received += 1
                rtts.append(rtt)
            packet_count += 1
            time.sleep(args.wait)
    except:
        end_time = time.time()
        total_time = (end_time - start_time) * 1000
        loss = 100 - (received / packet_count) * 100
        print(f'\n{args.dest} ping statistics:')
        print(f'\t{packet_count} packets transmitted, {received} packets received, {loss}% packet loss, time {total_time:.2f}ms')
        print(f'\trtt min/avg/max: {min(rtts):.2f}/{sum(rtts)/len(rtts):.2f}/{max(rtts):.2f}')
    if received == 0:
        retval = 1
    return retval

if __name__ == '__main__':
    main()
