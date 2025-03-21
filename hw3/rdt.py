max_pkt_size = 5

def checksum(data):
    csum = 0x0
    for b in data.encode():
        csum += b
    
    csum = csum ^ 0xFFFF
    return csum


def create_pkt(src, dst, seq, ack, data):
    length = len(data) + 48
    chksum = checksum(data)
    pkt = f'{src}/{dst}/{length}/{chksum}/{seq}/{ack}/{data}'
    print(pkt)
    return pkt.encode()
