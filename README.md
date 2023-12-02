# ARP Spoofing Script

## Overview
This is a Python script for ARP (Address Resolution Protocol) spoofing. ARP spoofing is a technique where an attacker sends fake ARP messages onto a local area network to link their MAC address with the IP address of another device on the network. This can be used for various purposes, including network monitoring, MITM (Man-in-the-Middle) attacks, or network troubleshooting.
## Theoretical Part

## Ethernet Frame Structure and ARP
### Ethernet Frame Header:
The Ethernet frame header is a crucial part of data transmission over Ethernet networks. It provides the necessary information for the network devices to correctly send and receive data packets. The key components of an Ethernet frame header include:

**Source MAC Address:** This field contains the MAC (Media Access Control) address of the sender, identifying the source device.

**Destination MAC Address:** It contains the MAC address of the intended recipient, specifying where the data should be delivered.

**Ethernet Type or Length:** This field indicates the type of payload encapsulated within the frame. For ARP, the type value is typically set to 0x0806, denoting ARP.

### ARP Payload:
### what is arp?
The Address Resolution Protocol (ARP) is a fundamental networking protocol used to map an IP address to a physical (MAC) address on a local network. ARP is essential for devices on the same network to communicate with each other efficiently.
The ARP payload within an Ethernet frame includes these components:

**Hardware Type:** Specifies the type of network hardware used (e.g., Ethernet).

**Protocol Type:** Indicates the higher-layer protocol being used (usually IPv4).

**Hardware Address Length and Protocol Address Length:** These fields specify the lengths of the hardware (MAC) and protocol (IP) addresses, typically 6 and 4 bytes for Ethernet and IPv4, respectively.

**Operation:** This field specifies the type of ARP message, such as ARP request (1) or ARP reply (2).

**Sender MAC and IP Addresses:** These fields contain the MAC and IP addresses of the sender (the device originating the ARP request or reply).

**Target MAC and IP Addresses:** These fields hold the MAC and IP addresses of the target device for which the ARP operation is intended.

**In summary, the Ethernet frame header is responsible for the overall structure of data packets on an Ethernet network, ensuring proper addressing and routing. Within this frame, the ARP payload is used for address resolution, allowing devices to discover each other's MAC addresses when communicating over an IP network.**

![CHEESE!](https://ipcisco.com/wp-content/uploads/2018/10/arp-packet-format-ipcisco.jpg)
### How Does ARP Work?
**ARP Request:** When a device, let's call it Device A, wants to find the MAC address of another device (Device B) with a known IP address, it sends an ARP request. This request is broadcast to all devices on the local network.

**ARP Reply:** Device B, with the matching IP address, responds with its MAC address to Device A. This information is then cached in Device A's ARP table for future use.

**ARP Caching:** The ARP information is cached so that Device A doesn't need to send ARP requests for the same IP address again in the near future. Caching improves network efficiency.

![CHEESE!](https://freecontent.manning.com/wp-content/uploads/Learn-Cisco-Administration-ARP.gif)

**Note:** ARP requests are broadcast. Before a computer sends ARP requests, it checks its ARP cache.

### What is ARP Spoofing?
ARP spoofing is a cyberattack technique where an attacker manipulate the Address Resolution Protocol (ARP) to associate their MAC address with the IP address of a legitimate device on a network. This allows them to intercept, redirect, or alter network traffic. It's often used in man-in-the-middle (MITM) attacks, placing the attacker between two parties to eavesdrop or manipulate data. ARP spoofing executes by broadcasting fake ARP responses, convincing devices that the attacker's MAC address is associated with a specific IP address, leading to traffic redirection.
In the provided Python script, ARP spoofing is achieved by creating and sending fake ARP responses to two devices, making them believe the attacker's device is the other device.

![CHEESE!](https://www.cs.toronto.edu/~arnold/427/15s/csc427/tools/CainAndAbel/images/image03.gif)
## Running the ARP Spoofing

To run the ARP spoofing script, you'll need to specify the target IP, the IP you want to spoof,your mac address and your network interface. Below are the steps:

   **Run the Script:**

   Execute the script using the following command:

   ```bash
   python arp_spoof.py -I eth0 -spoofip <spoof_ip> -targetip <target_ip> -mac <your_mac> -localip <local_ip>
   ```


## Requirements
- Python: Make sure you have Python installed on your system.
- Network Interface: You need to specify the network interface name (e.g., "enp0s3", "eth0") that is connected to the target network.
- IP Addresses: Specify the target IP address and the IP address you want to spoof.

# Legal Disclaimer 
The use of this code is only endorsed by the developers in those circumstances directly related to educational environments or authorized penetration testing engagements whose declared purpose is that of finding and mitigating vulnerabilities in systems, limiting their exposure to compromises and exploits employed by malicious agents as defined in their respective threat models.
