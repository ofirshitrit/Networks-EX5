from scapy.all import *
from scapy.layers.inet import TCP


def sniff_telnet_packet(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        # Check if the packet is Telnet traffic (destination port 23)
        if packet[TCP].dport == 23:
            # Extract the data part of the packet
            data = packet[Raw].load
            print("Telnet data:", data)


def main():
    # Sniff Telnet packets on the network interface
    sniff(filter="tcp", prn=sniff_telnet_packet)


if __name__ == "__main__":
    main()
