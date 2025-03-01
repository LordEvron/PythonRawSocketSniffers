# -*- coding: utf-8 -*-
"""
-------------------------------------------------------------------------------
AF_PACKET.py

Author: Lord Evron
Date:   01-March-2025
Version: 1.0.0

Description:
    An Example of script that captures IP packets using AF_PACKET sockets

Usage:
    Script need root permissions to capture packet from network interface

License:
    MIT

-------------------------------------------------------------------------------
"""

import socket
import struct
import binascii

INTERFACE_NAME = "wlp0s20f3"  # Replace with your network interface

def capture_packets(interface):
    """Captures network packets using AF_PACKET sockets."""

    try:
        # Create a raw socket using AF_PACKET
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) # 3 is ETH_P_ALL
        raw_socket.bind((interface, 0)) # Bind to the specified interface.
    except socket.error as msg:
        print(f"Socket creation failed: {msg}")
        return

    print(f"Capturing packets on interface: {interface}")

    try:
        while True:
            # Receive a packet
            packet, address = raw_socket.recvfrom(65535) # Max packet size
            ethernet_header = packet[:14]
            ethernet_data = packet[14:]

            # Unpack the Ethernet header
            ethernet_header_unpacked = struct.unpack("!6s6sH", ethernet_header)
            dest_mac = binascii.hexlify(ethernet_header_unpacked[0]).decode('utf-8')
            src_mac = binascii.hexlify(ethernet_header_unpacked[1]).decode('utf-8')
            eth_type = ethernet_header_unpacked[2]

            print(f"Destination MAC: {dest_mac}")
            print(f"Source MAC: {src_mac}")
            print(f"Ethernet Type: {hex(eth_type)}")

            if eth_type == 0x0800: # IP packet
                ip_header = ethernet_data[:20]
                ip_header_unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)
                src_ip = socket.inet_ntoa(ip_header_unpacked[8])
                dest_ip = socket.inet_ntoa(ip_header_unpacked[9])
                protocol = ip_header_unpacked[6] #Protocol number
                print(f"Protocol: {protocol}")
                print(f"Source IP: {src_ip}")
                print(f"Destination IP: {dest_ip}")

                if protocol == 17: #UDP protocol number is 17
                    udp_header = ethernet_data[20:28] #UDP header is 8 bytes.
                    udp_header_unpacked = struct.unpack("!HHHH", udp_header)
                    src_port = udp_header_unpacked[0]
                    dest_port = udp_header_unpacked[1]
                    length = udp_header_unpacked[2]
                    checksum = udp_header_unpacked[3]
                    udp_data = ethernet_data[28:length+20] #UDP data starts after the UDP header.

                    print(f"Source Port: {src_port}")
                    print(f"Destination Port: {dest_port}")
                    print(f"UDP Length: {length}")
                    print(f"UDP Checksum: {checksum}")
                    print(f"UDP Data: {binascii.hexlify(udp_data)}")

            # Add more parsing logic for other protocols (TCP, etc.) .

            print("-" * 40)

    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
    finally:
        raw_socket.close()

if __name__ == "__main__":
    capture_packets(INTERFACE_NAME)
