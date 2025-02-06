"""
packet analyzer script, with multiple possible filters
"""
import argparse
import pyshark



def read_file(filename, count=-1):
    """read pcap file and parse packet info
    filename: name of pcap file
    count: number of packets to read, default is whole file
    returns array with packet info"""
    capture = pyshark.FileCapture(filename)
    file_info = []
    counter = 0
    for packet in capture:
        if counter == count and count != -1:
            return file_info
        
        # ethernet header
        if hasattr(packet, 'eth'):
            size = packet.length
            dest_mac_addr= packet.eth.dst
            src_mac_addr = packet.eth.src
            type = packet.eth.type

        # ip header
        if hasattr(packet, 'ip'):
            version = packet.ip.version
            header_len = packet.ip.hdr_len
            type_of_service = packet.ip.dsfield
            total_len = packet.ip.len
            id = packet.ip.id
            flags = packet.ip.flags
            frag_offset = packet.ip.frag_offset
            time_to_live = packet.ip.ttl
            protocol = packet.ip.proto
            header_checksum = packet.ip.checksum
            src_ip_addr = packet.ip.src
            dest_ip_addr = packet.ip.dst
        
        protocol_type = packet.transport_layer

        # encapsulated packets
        encap = ''
        if hasattr(packet, 'tcp'):
            encap += 'tcp '
            src_port = packet.tcp.srcport
            dest_port = packet.tcp.dstport
        if hasattr(packet, 'udp'):
            encap += 'udp '
            src_port = packet.udp.srcport
            dest_port = packet.udp.dstport
        if hasattr(packet, 'icmp'):
            encap += 'icmp '
            protocol_type = 'ICMP'

        info = {'size': size, 'dest_mac': dest_mac_addr, 'src_mac': src_mac_addr, 'type': type, 
                'version': version, 'header_len': header_len, 'tos': type_of_service, 'total_len': total_len,
                'id': id, 'flags': flags, 'frag_offset': frag_offset, 'ttl': time_to_live, 'protocol': protocol,
                'header_checkum': header_checksum, 'src_ip': src_ip_addr, 'dest_ip': dest_ip_addr, 
                'protocol_type': protocol_type, 'encapsulated': encap, 'src_port': src_port, 'dest_port': dest_port}
        file_info.append(info)

        counter += 1
    
    return file_info


def filter(packet_info, func):
    """filters out packets based on input function
    packet_info: list of packets to filter
    func: function to filter on
    returns filtered list of packets"""
    filtered_packets = []
    for packet in packet_info:
        if func(packet):
            # print(packet)
            filtered_packets.append(packet)
    return filtered_packets


def main():
    """main function that parses arguments and runs other functions"""
    parser = argparse.ArgumentParser()
    parser.add_argument('-r')
    # parser.add_argument('filename')
    parser.add_argument('-host')
    parser.add_argument('-port')
    parser.add_argument('-ip', action='store_true')
    parser.add_argument('-tcp', action='store_true')
    parser.add_argument('-udp', action='store_true')
    parser.add_argument('-icmp', action='store_true')
    parser.add_argument('-net')
    parser.add_argument('-c', '--count', type=int)
    args = parser.parse_args()

    if not args.r:
        print('no file given')
        return
    print(f'reading: {args.r}')

    if args.count:
        file_info = read_file(args.r, args.count)
    else:
        file_info = read_file(args.r)
    print(f'{len(file_info)} packets analyzed')
    packet_info = file_info

    if args.host:
        print(f'filtering on host: {args.host}')
        packet_info = filter(packet_info, lambda p : p['src_ip'] == args.host or p['dest_ip'] == args.host)

    if args.port:
        print(f'filtering on port: {args.port}')
        packet_info =  filter(packet_info, lambda p : p['src_port'] == args.port or p['dest_port'] == args.port)

    if args.ip:
        # not sure exactly what this is supposed to do, currently only selects ipv4 packets
        print(f'filtering on ip')
        packet_info = filter(packet_info, lambda p : p['version'] == '4')
    
    if args.tcp:
        print(f'filtering on tcp')
        packet_info =  filter(packet_info, lambda p : p['protocol_type'] == 'TCP')

    if args.udp:
        print(f'filtering on udp')
        packet_info =  filter(packet_info, lambda p : p['protocol_type'] == 'UDP')

    if args.icmp:
        print(f'filtering on icmp')
        packet_info = filter(packet_info, lambda p : p['protocol_type'] == 'ICMP')

    if args.net:
        network = args.net.split('.')
        network = f'{network[0]}.{network[1]}.{network[2]}'
        print(f'filtering on network: {network}')
        packet_info = filter(packet_info, lambda p : p['src_ip'].startswith(network) or p['dest_ip'].startswith(network))

    print('packets:')
    for packet in packet_info:
        print(packet)

if __name__ == '__main__':
    main()