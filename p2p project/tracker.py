import time
import socket


s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tr_port = 9000
s.bind(('127.0.0.1', tr_port))


def main():
    while 1:
        pkt, _ = s.recvfrom()


if __name__ == '__main__':
    main()
