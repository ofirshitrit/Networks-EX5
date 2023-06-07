import sys
from scapy.all import  send
from scapy.layers.inet import ICMP, UDP, TCP, IP


def send_raw_ip_packet(packet):
    send(packet, verbose=False)


def icmp():
    ip_header = IP(src="1.2.3.4", dst="10.0.2.15")
    icmp_packet = ICMP(type=8)  # ICMP Type: 8 is request, 0 is reply
    packet = ip_header / icmp_packet
    send_raw_ip_packet(packet)


def udp():
    ip_header = IP(src="10.0.2.15", dst="10.0.2.15")
    udp_packet = UDP(sport=12345, dport=9090)
    data = "Evil Hacker!\n"
    packet = ip_header / udp_packet / data
    send_raw_ip_packet(packet)


def tcp():
    ip_header = IP(src="1.2.3.4", dst="10.0.2.15")
    tcp_packet = TCP(sport=12345, dport=9090, seq=1)
    data = "Evil Hacker!\n"
    packet = ip_header / tcp_packet / data
    send_raw_ip_packet(packet)


def main():
    # icmp()
    # print("ICMP sent")
    #
    # udp()
    # print("UDP sent")
    #
    tcp()
    print("TCP sent")


if __name__ == "__main__":
    main()
