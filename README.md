# Raw Socket Packet Capture Scripts

This repository contains two Python scripts demonstrating network packet capture using raw sockets: `AF_INET.py` and `AF_PACKET.py`.
If you want to learn more, check out my articles on [sockets](https://lukemainframe.top/2021/05/27/socket-families/) or the one specific to [this code](https://lukemainframe.top/2025/02/28/raw-socket-sniffer-with-python/)

## AF_PACKET.py

**Description:**

`AF_PACKET.py` captures Ethernet frames using `socket.AF_PACKET`, `socket.SOCK_RAW`, and `socket.htons(3)` (or `ETH_P_ALL`). It provides comprehensive visibility into all network traffic on the local network segment, operating at the data link layer (Layer 2).

**Usage:**

1.  **Prerequisites:**
    * Python 3 installed.
    * Root or `sudo` privileges.

2.  **Run the script:**
    ```bash
    sudo python AF_PACKET.py
    ```

3.  **Replace the default interface:**
    * Modify the `interface_name` variable in the `if __name__ == "__main__":` block to the name of your network interface (e.g., "eth0", "wlan0").

**Key Features:**

* Captures all Ethernet frames on the network segment.
* Parses Ethernet, IP, and TCP/UDP headers.
* Provides comprehensive visibility into all network protocols.
* Requires manual parsing of headers.

**Notes:**

* This script requires root privileges to create raw sockets.
* It captures all traffic on the specified network interface.


## AF_INET.py

**Description:**

`AF_INET.py` captures IP packets containing TCP segments using `socket.AF_INET`, `socket.SOCK_RAW`, and `socket.IPPROTO_TCP`. It focuses on capturing traffic at the IP layer (Layer 3) and provides a targeted approach for analyzing TCP communication.

**Usage:**

1.  **Prerequisites:**
    * Python 3 installed.
    * Root or `sudo` privileges.

2.  **Run the script:**
    ```bash
    sudo python AF_INET.py
    ```

3.  **Replace the default IP address:**
    * Modify the `ip_address` variable in the `if __name__ == "__main__":` block to the IP address of the network interface you want to monitor.

**Key Features:**

* Captures IP packets containing TCP segments.
* Parses IP and TCP headers.
* Filters out other protocols like UDP and ICMP.
* Requires binding to a specific IP address.

**Notes:**

* This script requires root privileges to create raw sockets.
* Binding to an IP address implicitly filters packets destined for or originating from that IP.
* It requires less parsing than AF_PACKET since the datagram header is not present.

## General Notes

* Both scripts require root or `sudo` privileges.
* Always be aware of the security implications of capturing network traffic.
* These scripts are examples, and for production use, consider using libraries like `scapy` which provide more robust functionality.


##  Additional Notes 

Eternal Glory to the Great Evron Empire!
