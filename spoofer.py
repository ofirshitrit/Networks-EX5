import socket
import struct
import select


def checksum(msg):
    s = 0
    n = len(msg) % 2
    for i in range(0, len(msg) - n, 2):
        s += (msg[i] << 8) + msg[i + 1]
    if n:
        s += msg[i + 1] << 8
    while (s >> 16):
        s = (s & 0xFFFF) + (s >> 16)
    s = ~s & 0xffff
    return s


def spoof_icmp_packet(src, dst):
    packet = struct.pack("!BBHHH", 8, 0, 0, 1, 1)
    chksum = checksum(packet)
    packet = struct.pack("!BBHHH", 8, 0, socket.htons(chksum), 1, 1)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    ip_header = struct.pack("!BBHHHBBH4s4s", 69, 0, len(packet), 0, 0, 64, socket.IPPROTO_ICMP, 0,
                            socket.inet_aton(src), socket.inet_aton(dst))

    # Send the packet
    s.sendto(ip_header + packet, (dst, 0))

    # Create a new socket to listen for responses
    r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    r.bind(('', 0))
    r.setblocking(0)

    while True:
        ready, _, _ = select.select([r], [], [], 1)
        if ready:
            response, addr = ready[0].recvfrom(4096)
            print(f"Response: {response}, Addr: {addr}")
        else:
            print("No response within timeout, exiting...")
            break


# def spoof_tcp_packet(src, dst):
#
#
#     # similar to ICMP spoofing but with IPPROTO_TCP and changing the packet to be TCP
#
# def spoof_udp_packet(src, dst):
#
#
#     # similar to ICMP spoofing but with IPPROTO_UDP and changing the packet to be UDP

def main():
    src = "1.2.3.4"
    dst = "10.0.2.15"
    spoof_icmp_packet(src, dst)
    print("ICMP packet sent!")
    # spoof_tcp_packet(src, dst)
    # spoof_udp_packet(src, dst)


if __name__ == "__main__":
    main()
