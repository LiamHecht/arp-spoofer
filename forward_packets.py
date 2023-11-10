import socket
import struct
import time

def manipulate_packet(packet):
    from sniffer import ethernet_head, ipv4_head, get_ip
    # packet = b"\x08\x00'\xd9\xb3\xb1\xd8^\xd3\x93\xbb\xf8\x08\x00E\x00\x00<Q\xe7\x00\x00\x80\x01\xd4\xbe\n\x00\x00\x01\n\x00\x00\x1b\x08\x00MY\x00\x01\x00\x02abcdefghijklmnopqrstuvwabcdefghi"
    # print(packet)
    print(packet)
    eth = ethernet_head(packet)
    dest_mac, source_mac, proto, data = ethernet_head(packet)
    ipv4 = ipv4_head(eth[3])
    source = get_ip(ipv4[4])
    target = get_ip(ipv4[5])


    # print("----------------------------")
    print(target)
    new_dest_mac = search_arp_cache(target)
    # new_source_mac = "d8:5e:d3:93:bb:f8"
    dest_mac = bytes.fromhex(new_dest_mac.replace(":", "")) 
    new_source_mac = bytes.fromhex(source_mac.replace(":", "")) 

    packet = dest_mac + new_source_mac + packet[12:]

    eth = ethernet_head(packet)

    ipv4 = ipv4_head(eth[3])
    source = get_ip(ipv4[4])
    target = get_ip(ipv4[5])

    print('\nEthernet Frame:')
    print('Destination: {}, Source: {}, Protocol: {}'.format(eth[0], eth[1], eth[2]))

    print('\t - IPv4 Packet:')
    print('\t\t - Version: {}, Header Length: {}, TTL: {}'.format(ipv4[0], ipv4[1], ipv4[2]))
    print('\t\t - Protocol: {}, Source: {}, Target: {}'.format(ipv4[3], source, target))
    return packet
def forward_packet(packet, interface):
    manipulated_packet = manipulate_packet(packet)
    
    if manipulated_packet is not None:
        # Open a raw socket for sending packets
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as s:
            # Replace 'eth0' with your network interface name
            s.bind((interface, 0))
            s.send(manipulated_packet)
    
    # Generate a unique filename based on a timestamp or any other identifier
    filename = f"packet_{int(time.time())}.txt"
    record_packet(manipulated_packet, filename)
    print("Packet sent")
def search_arp_cache(target_ip):
    try:
        with open('/proc/net/arp', 'r') as arp_cache_file:
            lines = arp_cache_file.readlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) == 6:
                    ip, _, _, mac, _, _ = parts
                    if ip == target_ip:
                        # Make sure the MAC address is in the correct format (00:11:22:33:44:55)
                        return mac
    except FileNotFoundError:
        print("ARP cache file not found. Make sure you are running this on a Linux system.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    return None

def record_packet(raw_data, filename):
    with open(filename, 'w') as file:
        file.write(str(raw_data))
        file.write("\n----------------------------------------------------------------------------------------\n")
# packet = b"\x08\x00'\xd9\xb3\xb1\xd8^\xd3\x93\xbb\xf8\x08\x00E\x00\x00<Q\xe7\x00\x00\x80\x01\xd4\xbe\n\x00\x00\x01\n\x00\x00\x1b\x08\x00MY\x00\x01\x00\x02abcdefghijklmnopqrstuvwabcdefghi"
# packet = b"\x08\x00'\xd9\xb3\xb1\xd8^\xd3\x93\xbb\xf8\x08\x00E\x00\x00<\xb0\xf7\x00\x00\x80\x01u\xae\n\x00\x00\x01\n\x00\x00\x1b\x08\x00MM\x00\x01\x00\x0eabcdefghijklmnopqrstuvwabcdefghi"
# new_p = manipulate_packet(packet)
# print(packet)
# print("----------------------------------------")
# print(new_p)

# forward_packet(packet, "enp0s3")