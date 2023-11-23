import sys
import struct
import socket

def get_mac_addr(bytes_addr):
    # Convert the bytes of MAC address to a string representation
    bytes_str = map('{:02x}'.format, bytes_addr)
    #create the MAC address with colons
    mac_addr = ':'.join(bytes_str)
    return mac_addr

def ethernet_head(raw_data):
    # Unpack Ethernet header
    dest, src, prototype = struct.unpack('! 6s 6s H', raw_data[:14])
    # Convert destination and source MAC addresses to readable format
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    # Convert the prototype field to a human-readable format
    proto = socket.htons(prototype)
    # Extract data after the Ethernet header
    data = raw_data[14:]
    return dest_mac, src_mac, proto, data

def icmp_head(raw_data):
    # Unpack ICMP header
    icmp_type, icmp_code, checksum = struct.unpack('! B B H', raw_data[:4])
    # Extract data after the ICMP header
    data = raw_data[4:]
    return icmp_type, icmp_code, checksum, data

def udp_head(raw_data):
    # Unpack UDP header 
    src_port, dest_port, length, checksum = struct.unpack('! H H H H', raw_data[:8])
    # Extract data after the UDP header
    data = raw_data[8:]
    return src_port, dest_port, length, checksum, data

def ipv4_head(raw_data):
    # Unpack IPv4 header 
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    # Extract data after the IPv4 header
    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src, target, data

def dns_head(raw_data):
    # Unpack DNS header
    transaction_id, flags, questions, answers, authority, additional = struct.unpack('! H H H H H H', raw_data[:12])
    # Extract data after the DNS header
    data = raw_data[12:]
    return transaction_id, flags, questions, answers, authority, additional, data

def arp_head(raw_data):
    # The ARP packet structure consists of several fields
    hardware_type, protocol_type, hardware_size, protocol_size, opcode = struct.unpack('! H H B B H', raw_data[:8])
    
    # Check if it's an ARP request or reply based on the opcode
    arp_operation = "ARP Request" if opcode == 1 else "ARP Reply"
    
    sender_mac = get_mac_addr(raw_data[8:14])
    sender_ip = get_ip(raw_data[14:18])
    target_mac = get_mac_addr(raw_data[18:24])
    target_ip = get_ip(raw_data[24:28])
    
    return hardware_type, protocol_type, hardware_size, protocol_size, arp_operation, sender_mac, sender_ip, target_mac, target_ip

def get_ip(addr):
     return '.'.join(map(str, addr))
 
def tcp_head(raw_data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0b00111111
    flag_urg = (flags & 0b100000) >> 5
    flag_ack = (flags & 0b010000) >> 4
    flag_psh = (flags & 0b001000) >> 3
    flag_rst = (flags & 0b000100) >> 2
    flag_syn = (flags & 0b000010) >> 1
    flag_fin = flags & 0b000001
    data = raw_data[offset:]
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data

def format_multi_line(prefix, text):
    if isinstance(text, bytes):
        try:
            text = text.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            text = "Unreadable or non-UTF-8 data"

    lines = text.split('\n')
    formatted_lines = [f"{prefix}{line}" for line in lines]
    return '\n'.join(formatted_lines)
      
def sniff_packets(interface, target1_ip, target2_ip):
    from forward_packets import forward_packet
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = s.recvfrom(65535)
        eth = ethernet_head(raw_data)

        if eth[2] == 8:  # IPv4
            ipv4 = ipv4_head(eth[3])
            source = get_ip(ipv4[4])
            target = get_ip(ipv4[5])


            if (source == target1_ip and target == target2_ip) or (source == target2_ip and target == target1_ip):
                print(raw_data)
                print(addr)
                print("This packet should be forwarded.")
                forward_packet(raw_data, interface)
        analyze_packet(raw_data, addr)

def analyze_packet(raw_data, addr):
    eth = ethernet_head(raw_data)
    print('\nEthernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))
    if eth[2] == 8:  # IPv4
        ipv4 = ipv4_head(eth[3])
        source = get_ip(ipv4[4])
        target = get_ip(ipv4[5])

        print('\t - IPv4 Packet:')
        print('\t\t - Version: {}, Header Length: {}, TTL: {}'.format(ipv4[0], ipv4[1], ipv4[2]))
        print('\t\t - Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], source, target))
        if ipv4[3] == 6:  # TCP
            print(ipv4[6])
            tcp = tcp_head(ipv4[6])
            print('\t\t - TCP Segment:')
            print('\t\t\t - Source Port: {}, Destination Port: {}'.format(tcp[0], tcp[1]))
            print('\t\t\t - Sequence: {}, Acknowledgment: {}'.format(tcp[2], tcp[3]))
            print('\t\t\t - Flags:')
            print('\t\t\t\t - URG: {}, ACK: {}, PSH: {}'.format(tcp[4], tcp[5], tcp[6]))
            print('\t\t\t\t - RST: {}, SYN: {}, FIN: {}'.format(tcp[7], tcp[8], tcp[9]))
            if len(tcp[10]) > 0:
                print('\t\t - TCP Data:')
            if tcp[1] == 80:
                print('\t\t - HTTP Traffic (port 80)')
            elif tcp[1] == 443:
                print('\t\t - HTTPS Traffic (port 443)')
        elif ipv4[3] == 1:  # ICMP
            icmp = icmp_head(ipv4[6])
            print('\t\t - ICMP Packet:')
            print('\t\t\t - Type: {}, Code: {}, Checksum: {}'.format(icmp[0], icmp[1], icmp[2]))
            if len(icmp[3]) > 0:
                print('\t\t - ICMP Data:')
        elif ipv4[3] == 17:  # UDP
            udp = udp_head(ipv4[6])
            print('\t\t - UDP Segment:')
            print('\t\t\t - Source Port: {}, Destination Port: {}'.format(udp[0], udp[1]))
            print('\t\t\t - Length: {}, Checksum: {}'.format(udp[2], udp[3]))
            if udp[1] == 53:
                dns = dns_head(udp[4])
                print('\t\t\t - DNS Packet:')
                print('\t\t\t\t - Transaction ID: {}'.format(dns[0]))
                print('\t\t\t\t - Flags: {}'.format(dns[1]))
                print('\t\t\t\t - Questions: {}'.format(dns[2]))
                print('\t\t\t\t - Answers: {}'.format(dns[3]))
                print('\t\t\t\t - Authority: {}'.format(dns[4]))
                print('\t\t\t\t - Additional: {}'.format(dns[5]))
    elif eth[2] == 1544:  # ARP
        arp = arp_head(eth[3])
        print('\t - ARP Packet:')
        print('\t\t - Hardware Type: {}, Protocol Type: {}'.format(arp[0], arp[1]))
        print('\t\t - Hardware Size: {}, Protocol Size: {}'.format(arp[2], arp[3]))
        print('\t\t - Operation: {}'.format(arp[4]))
        print('\t\t - Sender MAC: {}, Sender IP: {}'.format(arp[5], arp[6]))
        print('\t\t - Target MAC: {}, Target IP: {}'.format(arp[7], arp[8]))

    
# if __name__ == "__main__":
#     sniff_packets()