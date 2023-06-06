from scapy.all import *
import sys

from scapy.layers.inet import IP, ICMP


def traceroute(dest):
    ttl = 1
    max_ttl = 30

    print('traceroute to %s' % dest)

    while True:
        #  an IP packet is created with the destination the TTL.
        # The ICMP() function creates an ICMP Echo Request packet.
        p = IP(dst=dest, ttl=ttl) / ICMP()
        # The sr1() function sends the packet and waits for a single response packet, storing it in the reply variable.
        reply = sr1(p, verbose=0)

        if reply is None:
            print('no response')
            break
        elif reply[ICMP].type == 11 and reply[ICMP].code == 0:  # Time Exceeded
            print('route %d: %s' % (ttl, reply.src))
            ttl += 1
        elif reply[ICMP].type == 0:  # Echo Reply
            print('route %d: %s (destination reached)' % (ttl, reply.src))
            break
        else:
            print('unexpected reply')
            break

        if ttl > max_ttl:
            print('maximum TTL exceeded')
            break


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: python traceroute.py <destination>')
        sys.exit(1)

    dest = sys.argv[1]
    traceroute(dest)
