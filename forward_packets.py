import socket
import struct
import time

def manipulate_packet(packet):
    from sniffer import ethernet_head, ipv4_head, get_ip
    print(packet)
    eth = ethernet_head(packet)
    dest_mac, source_mac, proto, data = ethernet_head(packet)
    ipv4 = ipv4_head(eth[3])
    source = get_ip(ipv4[4])
    target = get_ip(ipv4[5])


    print(target)
    new_dest_mac = search_arp_cache(target)
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
            s.bind((interface, 0))
            s.send(manipulated_packet)
    
    # Generate a unique filename based on a timestamp 
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
                        return mac
    except FileNotFoundError:
        print("ARP cache file not found. Make sure you are running this on a Linux system.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
    return None

def record_packet(raw_data, filename):
    with open(f"packets/{filename}", 'w') as file:
        file.write(str(raw_data))
