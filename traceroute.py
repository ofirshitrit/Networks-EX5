import socket
import struct
import time


def traceroute(destination, max_hops):
    port = 33434  # Port number used for traceroute

    for ttl in range(1, max_hops + 1):
        # Create a UDP socket
        icmp = socket.getprotobyname('icmp')
        udp = socket.getprotobyname('udp')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

        # Set the TTL value for the socket
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        # Set the timeout for receiving ICMP replies
        sock.settimeout(3.0)

        # Send an empty UDP packet to the destination
        sock.sendto(b"", (destination, port))

        try:
            # Receive the ICMP reply packet and get the source IP address
            _, addr = sock.recvfrom(512)
            addr = addr[0]

            # Print the TTL and source IP address
            print(f"{ttl}: {addr}")

            # Check if the destination is reached
            if addr == destination:
                break

        except socket.timeout:
            # Print an asterisk if there is no response within the timeout
            print(f"{ttl}: *")

        finally:
            # Close the socket
            sock.close()


# Example usage
traceroute("google.com", 30)
