from scapy.all import *
import sys

from scapy.layers.inet import IP, ICMP


def traceroute(dest):
    ttl = 1
    max_ttl = 30

    print('traceroute to %s' % dest)

    while True:
        p = IP(dst=dest, ttl=ttl) / ICMP()
        reply = sr1(p, verbose=0)

        if reply is None:
            print('no response')
            break
        elif reply[ICMP].type == 11 and reply[ICMP].code == 0:  # Time Exceeded
            print('hop %d: %s' % (ttl, reply.src))
            ttl += 1
        elif reply[ICMP].type == 0:  # Echo Reply
            print('hop %d: %s (destination reached)' % (ttl, reply.src))
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
