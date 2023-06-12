from scapy.all import *
import struct

from scapy.layers.inet import ICMP, IP


def in_cksum(packet):
    """Calculate the Internet Checksum of the given packet"""
    words = bytes(packet)
    sum = 0
    for i in range(0, len(words), 2):
        if i + 1 >= len(words):
            sum += words[i]
        else:
            w = words[i] + (words[i + 1] << 8)
            sum += w
    while (sum >> 16) > 0:
        sum = (sum & 0xFFFF) + (sum >> 16)

    return ~sum & 0xFFFF


def got_packet(packet):
    if ICMP in packet and packet[ICMP].type == 8:  # Echo Request
        print("     GOT PACKET")
        print("       From: {}".format(packet[IP].src))
        print("         To: {}".format(packet[IP].dst))

        # Create a response packet
        ip = IP(src=packet[IP].dst, dst=packet[IP].src, ihl=packet[IP].ihl, ttl=20)
        icmp = ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)

        # Calculate Checksum
        payload_len = len(packet[ICMP].payload)
        icmp_data = struct.pack("!BBHHH", icmp.type, icmp.code, 0, icmp.id, icmp.seq) + packet[ICMP].payload.original
        icmp.chksum = in_cksum(icmp_data)

        # Combine IP and ICMP
        response_packet = ip / icmp / packet[ICMP].payload
        send(response_packet)


def main():
    # Get the list of available interfaces
    iface_list = get_if_list()

    # Find the first interface that starts with "br-"
    iface = next((i for i in iface_list if i.startswith("br-")), None)

    if iface:
        # Sniff ICMP packets on the chosen interface
        sniff(filter="icmp", prn=got_packet, iface=iface)
    else:
        print("No interface starting with 'br-' found.")


if __name__ == "__main__":
    main()
