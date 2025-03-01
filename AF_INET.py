# -*- coding: utf-8 -*-
"""
-------------------------------------------------------------------------------
AF_INET.py

Author: Lord Evron
Date:   01-March-2025
Version: 1.0.0

Description:
    An Example of script that captures IP packets using AF_INET sockets

Usage:
    Script need root permissions to capture packet from network interface

License:
    MIT

-------------------------------------------------------------------------------
"""

import socket
import struct
import binascii

IP_ADDRESS = "10.0.0.25" #"192.168.1.X"  # Replace with your IP address

def capture_packets(ip_address): # Takes an IP address
    """Captures IP packets using AF_INET sockets."""

    try:
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw_socket.bind((ip_address, 0)) # Binds to the IP address
    except socket.error as msg:
        print(f"Socket creation failed: {msg}")
        return

    print(f"Capturing IP packets on IP: {ip_address}")


    try:
        while True:
            # Receive a packet
            packet, address = raw_socket.recvfrom(65535) # Max packet size
            ip_header = packet[:20]
            ip_data = packet[20:]

            # Unpack the IP header
            ip_header_unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)
            src_ip = socket.inet_ntoa(ip_header_unpacked[8])
            dest_ip = socket.inet_ntoa(ip_header_unpacked[9])
            protocol = ip_header_unpacked[6]

            print(f"Source IP: {src_ip}")
            print(f"Destination IP: {dest_ip}")
            print(f"Protocol: {protocol}")

            if protocol == 6: #TCP protocol number is 6
                tcp_header = ip_data[:20] #TCP header is 20 bytes minimum
                tcp_header_unpacked = struct.unpack("!HHLLBBHHH", tcp_header)
                src_port = tcp_header_unpacked[0]
                dest_port = tcp_header_unpacked[1]
                seq_num = tcp_header_unpacked[2]
                ack_num = tcp_header_unpacked[3]
                data_offset = (tcp_header_unpacked[4] >> 4) * 4 #calculating data offset. *4 because the offset is specified in 32 bit words
                tcp_data = ip_data[data_offset:]

                print(f"Source Port: {src_port}")
                print(f"Destination Port: {dest_port}")
                print(f"Sequence Number: {seq_num}")
                print(f"Acknowledgement Number: {ack_num}")
                print(f"TCP Data: {binascii.hexlify(tcp_data)}")

            print("-" * 40)

    except KeyboardInterrupt:
        print("\nPacket capture stopped.")
    finally:
        raw_socket.close()

if __name__ == "__main__":
    capture_packets(IP_ADDRESS)

