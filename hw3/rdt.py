"""
common code shared across the modules
"""

max_pkt_size = 5

def checksum(data):
    """
    compiutes checksum
    data: data to compute checksum on
    retunrs: checksum of data
    """
    csum = 0x0
    for b in data.encode():
        csum += b
    
    csum = csum ^ 0xFFFF
    return csum


def create_pkt(src, dst, seq, ack, data):
    """
    creates a 'packet' string object following udp header with
    added seq number and ack flag
    src: source port of the packet
    dst: destination port of the packet
    seq: sequence number of the packet
    ack: flag if packet is an ack or not
    data: data for the packet
    returns: encoded packet
    """
    length = len(data) + 48
    chksum = checksum(data)
    pkt = f'{src}/{dst}/{length}/{chksum}/{seq}/{ack}/{data}'
    print(pkt)
    return pkt.encode()
