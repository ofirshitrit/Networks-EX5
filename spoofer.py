# import socket
# import struct
#
#
# # Helper function to calculate the checksum
# def calculate_checksum(data):
#     # If the length is odd, pad the data with a null byte
#     if len(data) % 2 == 1:
#         data += b'\x00'
#
#     # Calculate the checksum
#     checksum = 0
#     for i in range(0, len(data), 2):
#         word = (data[i] << 8) + data[i + 1]
#         checksum += word
#
#     checksum = (checksum >> 16) + (checksum & 0xffff)
#     checksum += checksum >> 16
#
#     return (~checksum) & 0xffff
#
# def send_raw_ip_packet(ip_header):
#     # Step 1: Create a raw network socket.
#     sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
#
#     # Step 2: Set socket option.
#     sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
#
#     # Step 3: Provide needed information about the destination.
#     dest_info = (socket.inet_ntoa(ip_header[16:20]), 0)
#
#     # Step 4: Send the packet out.
#     sock.sendto(ip_header, dest_info)
#     sock.close()
#
#
# def icmp():
#     # Step 1: Fill in the ICMP header.
#     # Create a raw socket
#     sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
#
#     # ICMP header fields
#     icmp_type = 8  # ICMP Echo Request
#     icmp_code = 0  # No code for Echo Request
#     icmp_checksum = 0  # Placeholder for checksum
#     icmp_identifier = 12345  # Identifier for the request
#     icmp_sequence = 1  # Sequence number for the request
#
#     # Construct the ICMP header
#     icmp_header = struct.pack("!BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_identifier, icmp_sequence)
#
#     # Calculate the checksum
#     checksum = 0
#     icmp_header = icmp_header[:2] + struct.pack("!H", calculate_checksum(icmp_header)) + icmp_header[4:]
#
#     # Step 2: Fill in the IP header.
#     # IP header fields
#     ip_version = 4  # IP version (IPv4)
#     ip_header_length = 5  # Header length (5 words, 20 bytes)
#     ip_tos = 0  # Type of Service (default)
#     ip_total_length = 0  # Total length (placeholder)
#     ip_identifier = 54321  # Identifier
#     ip_flags = 0  # Flags (default)
#     ip_fragment_offset = 0  # Fragment offset (default)
#     ip_ttl = 255  # Time to Live
#     ip_protocol = socket.IPPROTO_ICMP  # Protocol (ICMP)
#     ip_checksum = 0  # Placeholder for checksum
#     ip_source = socket.inet_aton("1.2.3.4")  # Source IP address
#     ip_destination = socket.inet_aton("10.0.2.15")  # Destination IP address
#
#     # Construct the IP header
#     ip_header = struct.pack("!BBHHHBBH4s4s", (ip_version << 4) + ip_header_length, ip_tos, ip_total_length,
#                             ip_identifier, (ip_flags << 13) + ip_fragment_offset, ip_ttl, ip_protocol,
#                             ip_checksum, ip_source, ip_destination)
#
#     # Set the calculated checksum
#     ip_header = ip_header[:10] + struct.pack("!H", calculate_checksum(ip_header)) + ip_header[12:]
#
#     # Set the total length
#     ip_total_length = len(ip_header)
#     ip_header = ip_header[:2] + struct.pack("!H", ip_total_length) + ip_header[4:]
#
#     send_raw_ip_packet(ip_header)
#
#
# if __name__ == '__main__':
#     icmp()
#     print("ICMP sent")
#     #
#     # UDP()
#     # print("UDP sent")
#     #
#     # TCP()
#     # print("TCP sent")
import socket
import struct

def in_cksum(packet):
    if len(packet) % 2 != 0:
        packet += b'\x00'
    sum = 0
    countTo = len(packet) // 2 * 2
    count = 0
    while count < countTo:
        sum += packet[count + 1] * 256 + packet[count]
        sum &= 0xffffffff
        count += 2

    if countTo < len(packet):
        sum += packet[len(packet) - 1]
        sum &= 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum += sum >> 16
    answer = ~sum
    answer &= 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def send_raw_ip_packet(ip_header):
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.sendto(ip_header, ('10.0.2.15', 0))


def icmp():
    buffer = bytearray(1500)
    icmp_type = 8  # ICMP Type: 8 is request, 0 is reply

    # Step 1: Fill in the ICMP header
    icmp_header = struct.pack('!BBHHH', icmp_type, 0, 0, 0, 0)
    checksum = in_cksum(icmp_header)
    icmp_header = struct.pack('!BBHHH', icmp_type, 0, checksum, 0, 0)
    buffer[20:28] = icmp_header

    # Step 2: Fill in the IP header
    ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(icmp_header), 0, 64, 1, 0, 0, socket.inet_aton('1.2.3.4'),
                            socket.inet_aton('10.0.2.15'))
    buffer[0:20] = ip_header

    # Step 3: Finally, send the spoofed packet
    send_raw_ip_packet(buffer)


if __name__ == '__main__':
    icmp()
    print("ICMP sent")
