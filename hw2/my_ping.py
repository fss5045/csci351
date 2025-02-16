import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--count', type=int)
    parser.add_argument('-i', '--wait', type=int)
    parser.add_argument('-s', '--packetsize', type=int)
    parser.add_argument('-t', '--timeout', type=int)
    args = parser.parse_args()