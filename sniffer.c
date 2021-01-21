#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define MAX_IP_LEN 16
#define PACKET_BUFFER_SIZE 65536
	
void handle_packet(const uint8_t *pkt_buffer, uint16_t pkt_length){
	if (pkt_buffer == NULL) {
		return;
	}
	struct ethhdr *eth = (struct ethhdr*)pkt_buffer;
	struct iphdr *ip = (struct iphdr*)(pkt_buffer + sizeof(struct ethhdr));
	if(ip->protocol == IPPROTO_ICMP){
		int ip_header_len = ip->ihl * 4;
		struct icmphdr *icmp = (struct icmphdr*)(pkt_buffer + sizeof(struct ethhdr) + ip_header_len);
		
		struct sockaddr_in src_ip = { 0 };
		src_ip.sin_addr.s_addr = ip->saddr; 

		struct sockaddr_in dst_ip = { 0 };
		dst_ip.sin_addr.s_addr = ip->daddr;
		
		printf(" IP\n");
		printf("          From:%s\n", inet_ntoa(src_ip.sin_addr));
		printf("          To:%s\n", inet_ntoa(dst_ip.sin_addr));
		printf(" ICMP\n");
		printf("          Type:%d\n",(unsigned int)(icmp->type));
		printf("          Code:%d\n",(unsigned int)(icmp->code));
	}
}
int main(int argc, char* argv[]) {
	ssize_t data_size;
	uint8_t packet_buffer[PACKET_BUFFER_SIZE] = { 0 };
     // Create raw socket.
	int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (raw_socket == -1) {
		perror("socket");
	    return -1;
	}
	struct packet_mreq mr;
	mr.mr_type = PACKET_MR_PROMISC;
	// Trun on promiscuous mode.
	if (setsockopt(raw_socket, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) == -1) {
		perror("setsockopt");
		return -1;
	}
	for (;;) {
	        // receive packets:
		data_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, NULL, NULL);
		if (data_size == -1) {
			perror("recvfrom");
			return -1;
		}
		handle_packet(packet_buffer, data_size);
		}
		close(raw_socket);
		return 0;
}
