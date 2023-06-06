import os
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

    # Extract the flag fields from the TCP header
    cache_flag = (tcp_header[5] & 0x10) >> 4
    steps_flag = (tcp_header[5] & 0x08) >> 3
    type_flag = (tcp_header[5] & 0x04) >> 2
    status_code = (tcp_header[5] & 0x03)

    # Extract the cache control field from the TCP header
    cache_control = (tcp_header[6] & 0xFF00) >> 8

    # Convert the packet data to hexadecimal format
    hex_data = packet[54:].hex()  # Convert data to hexadecimal

    # Add line breaks every 40 characters in the hexadecimal data
    wrapped_data = '\n'.join(textwrap.wrap(hex_data, 40))

    # Create a dictionary containing the packet information
    packet_info = {
        'source_ip': source_ip,
        'dest_ip': dest_ip,
        'source_port': source_port,
        'dest_port': dest_port,
        'timestamp': timestamp,
        'total_length': total_length,
        'cache_flag': cache_flag,
        'steps_flag': steps_flag,
        'type_flag': type_flag,
        'status_code': status_code,
        'cache_control': cache_control,
        'data': wrapped_data
    }

    return packet_info


# Sniffer main function
def sniffer():
    print("The sniffer is working!")
    # Create a raw socket to sniff packets
    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Set file permissions to read/write
    file_name = '324249150_318964699.txt'
    os.chmod(file_name, 0o666)

    # Delete the file if it already exists
    if os.path.exists(file_name):
        os.remove(file_name)
        print("file delete!")

    # Open the file to write the captured packets
    file = open(file_name, 'w')
    print("file created!")

    packet_count = 0

    try:
        while True:
            # Receive a packet and retrieve the packet information
            packet = sniffer_socket.recvfrom(65535)[0]
            print("sniff packet number %d!" % packet_count)
            packet_info = format_packet(packet)

            # Write the packet information to the file
            print("write to the file")
            file.write(f"------got packet {packet_count}------\n")
            for key, value in packet_info.items():
                file.write(f"{key}: {value}\n")

            file.write('}\n')  # End of packet marker
            file.write('\n')

            packet_count += 1

            # Flush the file buffer
            file.flush()

    except KeyboardInterrupt:
        print("Sniffing stopped by the user.")

    finally:
        # Close the file and socket
        file.close()
        sniffer_socket.close()





# Start the sniffer
sniffer()
