import socket
import struct
import datetime

# Function to format the packet information
def format_packet(packet):
    ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
    source_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])

    tcp_header = struct.unpack('!HHLLBBHHH', packet[34:54])
    source_port = tcp_header[0]
    dest_port = tcp_header[1]

    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    total_length = len(packet)

    cache_flag = (tcp_header[5] & 0x10) >> 4
    steps_flag = (tcp_header[5] & 0x08) >> 3
    type_flag = (tcp_header[5] & 0x04) >> 2
    status_code = (tcp_header[5] & 0x03)

    cache_control = (tcp_header[6] & 0xFF00) >> 8

    data = packet[54:].hex()  # Convert data to hexadecimal

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
        'data': data
    }

    return packet_info

# Sniffer main function
def sniffer():
    # Create a raw socket to sniff packets
    sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    # Set the interface to promiscuous mode
    # sniffer_socket.bind(('YOUR_INTERFACE_NAME', 0))

    # Open a file to write the captured packets
    file_name = '324249150.txt' # TODO - add Maya taz
    file = open(file_name, 'w')

    try:
        while True:
            # Receive a packet and retrieve the packet information
            packet = sniffer_socket.recvfrom(65535)[0]
            packet_info = format_packet(packet)

            # Write the packet information to the file
            file.write(str(packet_info) + '\n')

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
