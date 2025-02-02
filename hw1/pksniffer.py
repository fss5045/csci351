import argparse
import pyshark


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-r')
    parser.add_argument('filename')
    parser.add_argument('-host')
    parser.add_argument('-port')
    parser.add_argument('-ip')
    parser.add_argument('-tcp')
    parser.add_argument('-udp')
    parser.add_argument('-icmp')
    parser.add_argument('-net')
    parser.add_argument('-c', '--count')
    args = parser.parse_args()
    print(f'reading: {args.filename}')

    if args.count:
        file_info = read_file(args.filename, int(args.count))
    else:
        file_info = read_file(args.filename)

    print(f'{len(file_info)} packets analyzed')
    print(file_info[0])


def read_file(filename, count=-1):
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
            protocol = packet.transport_layer
            header_checksum = packet.ip.checksum
            src_ip_addr = packet.ip.src
            dest_ip_addr = packet.ip.dst
        
        # encapsulated packets
        encap = ''
        if hasattr(packet, 'tcp'):
            encap += 'tcp '
        if hasattr(packet, 'udp'):
            encap += 'udp '
        if hasattr(packet, 'icmp'):
            encap += 'icmp '

        info = {'size': size, 'dest_mac': dest_mac_addr, 'src_mac': src_mac_addr, 'type': type, 
                'version': version, 'header_len': header_len, 'tos': type_of_service, 'total_len': total_len,
                'id': id, 'flags': flags, 'frag_offset': frag_offset, 'ttl': time_to_live, 'protocol': protocol,
                'header_checkum': header_checksum, 'src_ip': src_ip_addr, 'dest_ip': dest_ip_addr,
                'encapsulated': encap}
        file_info.append(info)

        counter += 1
    
    return file_info


main()
