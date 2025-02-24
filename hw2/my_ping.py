import argparse
import time
import subprocess
import platform

def send_packet(size, count, dest):
    sys = platform.system()
    command = ['ping']
    
    # cnt = str(count) if count else '1'

    if sys == 'Windows':
        command.append('-n')
        command.append('1')

        command.append('-l')
    else:
        command.append('-c')
        command.append('1')

        command.append('-s')

    command.append(size)
    command.append(dest)

    # print(command)
    result = subprocess.run(command, capture_output=True)
    return result.stdout.decode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--count', type=int)
    parser.add_argument('-i', '--wait', type=int, default=1)
    parser.add_argument('-s', '--packetsize', default='56')
    parser.add_argument('-t', '--timeout', type=int)
    parser.add_argument('dest')
    args = parser.parse_args()

    packet_count = 0
    start_time = time.time()
    while True:
        current_time = time.time()
        if args.timeout and current_time - start_time >= args.timeout:
            if args.count and packet_count < args.count:
                return 1
            break
        if packet_count > args.count:
            break
        out = send_packet(args.packetsize, args.count, args.dest)
        print(out)
        packet_count += 1
        time.sleep(args.wait)
    return 0

if __name__ == '__main__':
    main()
