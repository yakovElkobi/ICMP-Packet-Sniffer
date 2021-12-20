# ICMP-Packet-Sniffer
Ex4 - assigment was written for an assignment in the Computer Networking course at Ariel University.

# Part a my ping:
Modify the skeleton ICMP.cpp to create myping.cpp program.<br>

Requirements:
* myping sends ICMP ECHO REQUEST and receives ICMP-ECHO-REPLY (one time is enough)
* myping calculates the RTT time in milliseconds and microseconds.

Hints:
1)	To be able to read from the raw socket the reply, use instead of IPPROTO_RAW - IPPROTO_ICMP: socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
2)	Do not "cook" IP-header - delete that code.  Thus, with IPPROTO_ICMP the application is in charge only for ICMP packet, header and data, not for the IP-header. 
3)	"Cook" and add only ICMP, whereas kernel will add IPv4 header by itself.
4)	Remove setsockopt() IP_HDRINCL since we are not "cooking" the IP-header 
5)	When receiving, though, we are getting the whole IP packet and must extract the ICMP reply. 
6)	Note, that you get a copy of all ICMP packets sent to the host and should filter the relevant.
7)	Check the sent ICMP packet in Wireshark. If the checksum is not correct (zero), you missed to remove IP-header offset in ICMP-header checksum copying or calculations. 

# Part b sniffing:


