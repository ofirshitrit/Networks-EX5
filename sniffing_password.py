import socket
import struct
import datetime
import textwrap


# Function to format the packet information
def format_packet(packet):
    # Unpack the IP header
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
    # Extract the source and destination IP addresses
    source_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])

    # Unpack the TCP header
    tcp_header = struct.unpack('!HHLLBBHHH', packet[34:54])
    # Extract the source and destination ports
    source_port = tcp_header[0]
    dest_port = tcp_header[1]

    # Get the current timestamp in seconds
    timestamp = datetime.datetime.now().timestamp()
    # Get the total length of the packet
    total_length = len(packet)

    # Extract the data from the packet
    data = packet[54:]

    # Create a dictionary containing the packet information
    packet_info = {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'source_port': source_port,
        'dest_port': dest_port,
        'timestamp': timestamp,
        'total_length': total_length,
        'data': data
    }

    return packet_info


# Sniffer main function
def sniffer():
    print("The sniffer is working!")
    # Create a raw socket to sniff packets
    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    packet_count = 0

    try:
        while True:
            # Receive a packet and retrieve the packet information
            packet = sniffer_socket.recvfrom(65535)[0]
            print(f"Sniffed packet number {packet_count}!")

            packet_info = format_packet(packet)

            # Check if the packet is Telnet traffic (using port 23)
            if packet_info['source_port'] == 23 or packet_info['dest_port'] == 23:
                # Extract the data part of the packet
                data = packet_info['data']
                # Print the data part of the captured packet
                print("Data:")
                print(data.decode('utf-8'))
                print()

                # Manually mark where the password might be
                print("Possible password location: [ENTER YOUR MARKING HERE]")
                print()

            packet_count += 1

    except KeyboardInterrupt:
        print("Sniffing stopped by the user.")

    finally:
        sniffer_socket.close()


# Start the sniffer
sniffer()
