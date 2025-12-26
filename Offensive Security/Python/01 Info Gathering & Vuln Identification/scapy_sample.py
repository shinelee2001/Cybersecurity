from scapy.all import *
packet = rdpcap('http.cap') # read cap/pcap file

packet # shows the file overview. e.g., <http.cap: TCP41 UDP:2 ICMP:0 Other:0>

p = packet[0] # grab first packet in http.cap

p.show() # shows packet information with all wrapped packets in it. such as ethernet > IP > TCP > HTTP(RAW)

p[TCP] # find the first packet with TCP and set the packet.

p = IP()/TCP() # Create new packet with IP layer on TCP packet. By default src/dst = 127.0.0.1
p = IP(dst="8.8.8.8")/TCP(dport=53)
p = IP(dst="8.8.8.8")/UDP(dport=53)/DNS()