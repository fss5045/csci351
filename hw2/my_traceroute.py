import argparse
import time
import subprocess
import platform
import socket
import struct
import scapy.all as scapy


def trace(n, nqueries, summary, dest, timeout=5, max_hops=30):
    dest_ip = socket.gethostbyname(dest)
    icmp_type = 0 # 0 when using icmp, 3 when using udp

    ttl = 1
    while True:
        port = 33434
        unans = 0
        for q in range(nqueries):
            ip = scapy.IP(dst=dest_ip, ttl=ttl)
            udp = scapy.UDP(dport=port)

            # pkt = ip / udp makes reply always None beacause udp is blocked
            # pkt = ip / udp
            pkt = ip / scapy.ICMP()
            reply = scapy.sr1(pkt, timeout=timeout, verbose=0)

            if reply is None:
                unans += 1
                print(f'{ttl}\t*')
            else:
                if not n:
                    try:
                        host = socket.gethostbyaddr(reply.src)[0]
                        info = f'{ttl}\t{host}\t{reply.src}'
                    except socket.herror:
                        info = f'{ttl}\t???\t{reply.src}'
                else:
                    info = f'{ttl}\t{reply.src}'
                print(info)

                if reply.haslayer(scapy.ICMP) and reply[scapy.ICMP].type == icmp_type:
                    return 'Trace completed'
        
            port += 1

        if summary:
            print(f'{unans} unanswered probes for ttl {ttl}')

        ttl += 1
        if ttl > max_hops:
            break

    return 'Max hops exceeded'


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-n', action='store_true')
    parser.add_argument('-q', '--nqueries', type=int, default=3)
    parser.add_argument('-S', '--summary', action='store_true')
    parser.add_argument('dest')
    args = parser.parse_args()

    out = trace(args.n, args.nqueries, args.summary, args.dest)
    print(out)

if __name__ == '__main__':
    main()
