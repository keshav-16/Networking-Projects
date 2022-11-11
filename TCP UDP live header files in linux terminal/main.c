#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

//include header files that define ethernet, IP, UDP and TDP headers
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

typedef enum {false, true} bool;

int main(int argc, char *argv[])
{   
	//AF_PACKET    Low-level packet interface
	
	//SOCK_RAW	Provides raw network protocol access
	// The packes are not processed means no encapsulation and decapsulation
	//ETH_P_ALL	 Internet Protocol packet
	// Open raw socket and capture IP packets
	int raw_socket = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	
	//check for error
	if(raw_socket == -1)
	{
		perror("Error creating socket");
		exit(1);
	}

	//Create buffer to hold the packet information
	//Max packet size is 65535 bytes
	//65535 is max size in 16bits can store
	unsigned char *packet = (unsigned char *) malloc(65535);
	//0 out the memory
	memset(packet,0,65535);

	struct sockaddr source_addr;
	int saddr_len = sizeof(source_addr);
	while(1){
		int bytes_received = recvfrom(raw_socket,packet,65535,0,&source_addr,(socklen_t *)&saddr_len);
		
		if(bytes_received == -1)
		{
			perror("Error: ");
			exit(1);
		}
		
		// Packet structure is below 
		// [Ethernet Header 16 Bytes][IP Header 20-60 Bytes][Transport Layer Header][DATA]

		//---------Ethernet Header----------//
		//first 16 bytes are the ethernet header
		struct ethhdr *eth = (struct ethhdr *)(packet);

		//---------IP Header----------//
		//point to the ip header ==> packet + ethernet header size
		struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
		//get the ip header length. Multiply by 4 for the # of bytes
		unsigned int ip_header_length = ((unsigned int)ip->ihl)*4;

		//get the Transport layer protocol
		unsigned int t_proto = (unsigned int)ip->protocol;

		//Internet Address
		struct sockaddr_in source, dest;
		source.sin_addr.s_addr = ip->saddr;
		dest.sin_addr.s_addr = ip->daddr;

		//---------Transport Layer Header----------//
		//point to the TCP or UDP header
		// ==> packet + ethernet header size + IP header size (IHL)
		
		//if t_proto == 6, then the transport layer is TCP
		if(t_proto == 6){
			struct tcphdr *tcp = (struct tcphdr *)(packet + sizeof(struct ethhdr) + ip_header_length);
			unsigned char *data = (packet + sizeof(struct ethhdr) + ip_header_length + sizeof(struct tcphdr));

			printf("\033[1;43m************************************************************ TCP Packet ************************************************************\033[0m\n\n");
			printf("\033[1;32m------------------------- ETHERNET -------------------------\n");
			printf("Source MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("Destination MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("------------------------- IP -------------------------\n");
			printf("Total packet size: %d Bytes\n",ntohs(ip->tot_len));
			printf("IP Header Size: %d Bytes\n",ip_header_length);
			printf("IP Version: %d\n",ntohs(ip->version));
			printf("TTL: %d\n",ntohs(ip->ttl));
			printf("Protocol: %d\n",ntohs(ip->protocol));
			printf("Checksum: %d\n",ntohs(ip->check));
			printf("Source IP: %s\n",inet_ntoa(source.sin_addr));
			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
			printf("------------------------- TCP -------------------------\n");
			printf("Source Port: %d\n",ntohs(tcp->source));
			printf("Destination Port: %d\n",ntohs(tcp->dest));
			printf("Packet Sequence Number: %d \n",ntohs(tcp->seq));
			printf("Packet Acknowledgment Number: %d \n",ntohs(tcp->ack_seq));
			printf("Urgent Flag : %d \n",ntohs(tcp->urg));
			printf("Acknowledgement Flag : %d \n",ntohs(tcp->ack));
			printf("Push Flag : %d \n",ntohs(tcp->psh));
			printf("Reset Flag : %d \n",ntohs(tcp->rst));
			printf("Synchronise Flag  : %d \n",ntohs(tcp->syn));
			printf("Finish Flag  : %d \n",ntohs(tcp->fin));
			printf("Window : %d \n",ntohs(tcp->window));
			printf("Checksum : %d \n",ntohs(tcp->check));
			printf("Urgent Pointer : %d \n",ntohs(tcp->urg_ptr));
			int datalen = bytes_received - (sizeof(struct ethhdr) + ip_header_length + sizeof(struct tcphdr));
			printf("Theoretical total Data Size : %d bytes\n",datalen);
			printf("\033[0m");
			printf("\n\n\033[1;43m*************************************************************************************************************************************\033[0m\n\n");
		}
		//if t_proto == 17, then the transport layer is UDP
		else if(t_proto == 17){
			struct udphdr *udp = (struct udphdr *)(packet + sizeof(struct ethhdr) + ip_header_length);
			unsigned char *data = (packet + sizeof(struct ethhdr) + ip_header_length + sizeof(struct udphdr));

			printf("\033[1;104m************************************************************ UDP Packet ************************************************************\033[0m\n\n");
			printf("\033[1;95m------------------------- ETHERNET -------------------------\n");
			printf("Source MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("Destination MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("------------------------- IP -------------------------\n");
			printf("Total packet size: %d Bytes\n",ntohs(ip->tot_len));
			printf("IP Header Size: %d Bytes\n",ip_header_length);
			printf("IP Version: %d\n",ntohs(ip->version));
			printf("TTL: %d\n",ntohs(ip->ttl));
			printf("Protocol: %d\n",ntohs(ip->protocol));
			printf("Checksum: %d\n",ntohs(ip->check));
			printf("Source IP: %s\n",inet_ntoa(source.sin_addr));
			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
			printf("------------------------- UDP -------------------------\n");
			printf("Source Port: %d\n",ntohs(udp->source));
			printf("Destination Port: %d\n",ntohs(udp->dest));
			printf("UDP Header Size: %d Bytes\n",ntohs(udp->len));
			printf("UDP Checksum: %d \n",ntohs(udp->check));
			int datalen = bytes_received - (sizeof(struct ethhdr) + ip_header_length + sizeof(struct udphdr));
			printf("Theoretical total Data Size : %d bytes\n",datalen);
			printf("\033[0m");
			
			printf("\n\n*************************************************************************************************************************************\n\n");
		}
		else{
			printf("************************************************************ Packet ************************************************************\n\n");
			printf("------------------------- ETHERNET -------------------------\n");
			printf("Source MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);
			printf("Destination MAC Addr: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
			printf("------------------------- IP -------------------------\n");
			printf("Total packet size: %d Bytes\n",ntohs(ip->tot_len));
			printf("IP Header Size: %d Bytes\n",ip_header_length);
			printf("Source IP: %s\n",inet_ntoa(source.sin_addr));
			printf("Destination IP: %s\n",inet_ntoa(dest.sin_addr));
			printf("Transport Layer Protocol: %d\n",t_proto);
			printf("\n\n*************************************************************************************************************************************\n\n");
		}
	}
	//close socket after operation
	close(raw_socket);
	
	return 0;

}
