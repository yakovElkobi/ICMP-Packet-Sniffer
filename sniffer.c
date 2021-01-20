#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define MAX_IP_LEN 16
#define PACKET_BUFFER_SIZE 65536

sniff_packets(const char* interface_name){
	ssize_t data_size;
	uint8_t packet_buffer[PACKET_BUFFER_SIZE] = { 0 };
     // Create raw socket.
	int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (raw_socket == -1) {
		perror("socket");
	    return -1;
	}
	struct packet_mrep mr;
	mr.mr_type = PACKET_MR_PROMISC;
	// Trun on promiscuous mode.
	if (setsockopt(raw_socket, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mr, strlen(mr)) == -1) {
		perror("setsockopt");
		return -1;
	}
	for (;;) {
		data_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, NULL, NULL);
		if (data_size == -1) {
			perror("recvfrom");
			return -1;
		}
		print_packet(packet_buffer, data_size);
		}
	}
void print_packet(const uint8_t* pkt_buffer, uint16_t pkt_length){
	if (pkt_buffer == NULL) {
		return -1;
	}
	struct ethhdr* eth = (struct ethhdr*)pkt_buffer;
	struct ipheader *ip = (struct ipheader*)(pkt_buffer + sizeof(struct ethhdr));
	if(ip->iph_protocol == IPPROTO_ICMP){
		struct sockaddr_in src_ip = { 0 };
		src_ip.sin_addr.s_addr = iph->saddr;
		char src_ip_str[MAX_IP_LEN] = { 0 };
		strcpy(src_ip_str, inet_ntoa(src_ip.sin_addr)); 

		struct sockaddr_in dst_ip = { 0 };
		dst_ip.sin_addr.s_addr = iph->daddr;
		char dst_ip_str[MAX_IP_LEN] = { 0 };
		strcpy(dst_ip_str, inet_ntoa(dst_ip.sin_addr)); 

		printf("         From:%s\n, inet_ntoa(ip->iph_sorceip));
		
			printf("[%u]\n", );
	}
	
		
	
}
	
