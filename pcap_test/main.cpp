#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct ethernet_header{
	uint8_t dest[6];
	uint8_t source[6];
	uint16_t type;
} ETHER_HDR;

typedef struct ip_hdr
{
    uint8_t header_len :4; // 4 bit header length
    uint8_t version :4; //4-bit ip version
    uint8_t ip_tos; // 8 bit type of service
    uint16_t total_length; // 2 byte total length
    uint16_t ip_id; // 2 byte Unique identifier
 
    unsigned char ip_more_fragment :1;
    unsigned char ip_dont_fragment :1;
    unsigned char ip_reserved_zero :1;
 
 	uint8_t ip_frag_offset; // Fragment offset field
 
    uint8_t ip_ttl; // 1 byte TTL
    uint8_t protocol_id; // 1 byte protocol(TCP,UDP etc)
    uint16_t ip_checksum; // 2 byte IP checksum
    struct in_addr ip_srcaddr; // 4 byte source address
    struct in_addr ip_dstaddr; // 4 byte destination address
} IPV4_HDR;

typedef struct tcp_hdr{
	uint16_t tcp_srcport;
	uint16_t tcp_dstport;
	uint tcp_seqnum;
	uint tcp_acknum;
	u_char header_len1:4;
	u_char header_len2:4;
} TCP_HDR;

void usage() {
  printf("syntax: pcap_test enp1s0\n");
  printf("sample: pcap_test wlp2s0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
 	}

  while (true) {
    struct pcap_pkthdr* header;
    // u == unsigned
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    //Modify below codes
    //DO NOT CHEAT IT !!
    printf("\n%u bytes captured\n", header->caplen);

	//mac src, dst : 6bytes
    ETHER_HDR *eth;
    eth = (struct ethernet_header *)packet;
    int l3_protocol = ntohs(eth->type);
    printf("Source_MAC          : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",eth->source[0] , eth->source[1] , eth->source[2] , eth->source[3] , eth->source[4] , eth->source[5]);
    printf("Destination_MAC     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",eth->dest[0] , eth->dest[1] , eth->dest[2] , eth->dest[3] , eth->dest[4] , eth->dest[5]);
    printf("L3 protocol         : 0x%.4x \n" , l3_protocol );

    //verify upper layer
    //ip src, dst : 4bytes  && hex to ip   
    if(l3_protocol==0x0800){
    	IPV4_HDR *iph;
    	iph = (struct ip_hdr *)(packet+sizeof(struct ethernet_header));
    	int l4_protocol = iph->protocol_id;
        char ip_length = iph->header_len;

    	printf("Source_IP           : %s\n", inet_ntoa(*(struct in_addr*)&iph->ip_srcaddr));
    	printf("Destination_IP      : %s\n", inet_ntoa(*(struct in_addr*)&iph->ip_dstaddr));
    	printf("L4 Protocol         : 0x%x\n",l4_protocol);
    
    	//verify upper layer
    	//tcp src, dst : 2bytes && hex to decimal

        if(l4_protocol==0x06){
    		TCP_HDR *tcph;
    		tcph = (struct tcp_hdr *)((char *)iph+ip_length*4);
    		int tcph_size = int(tcph->header_len1)*4;
    		//printf("%u %lu",header->caplen,sizeof(struct ethernet_header)+sizeof(struct ip_hdr)+sizeof(struct tcp_hdr));
    		
    		printf("Source_Port         : %d\n", ntohs(tcph->tcp_srcport));
    		printf("Destination_Port    : %d\n", ntohs(tcph->tcp_dstport));
			
			if(sizeof(struct ethernet_header)+ip_length*4+tcph_size < iph->total_length){
				
                u_char *tcpp = (unsigned char *)((char *)tcph+tcph_size);
				printf("Data                : ");
				uint tcpp_length = iph->total_length - sizeof(struct ethernet_header)+ip_length*4+tcph_size;
                if(tcpp_length >= 16){
                    for(int i=0;i<16;i++){
    					printf("%.2X", tcpp[i]);
    				}
                }
                else{
                    for(int i=0;i<tcpp_length;i++){
                        printf("%.2X", tcpp[i]);
                    }
                }
				printf("\n");

			}
    	}
    	else{
    		printf("It's not following TCP Protcol\n");
    	}
    }
    else{
    	printf("It's not following IP Protocol\n");
    }

  }

  pcap_close(handle);
  return 0;
}
