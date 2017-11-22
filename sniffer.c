#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <arpa/inet.h>
#define ETHERTYPE_IP  0x0800 
#define ETHERTYPE_ARP  0x0806 
#define ETHERTYPE_RARP 0x8035  
#define ETHERTYPE_IPV6  0x86dd 

struct ether_h
{
	u_char	ether_dhost[6]; 
	u_char	ether_shost[6];
	u_short	ether_type;   
};

void getpacket(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)  
{  
	int	*id = (int *)arg;  
    int	i;
	struct	ether_h	*ether_protocol;
	u_short type;
	u_char	*mac;

	printf("id: %d\n", ++(*id));  
	printf("Packet length: %d\n",pkthdr->len);  
	printf("Number of bytes: %d\n",pkthdr->caplen);  
	printf("Recieved time: %s",ctime((const time_t *)&pkthdr->ts.tv_sec));   

	ether_protocol = (struct ether_h *)packet;

	type = ntohs(ether_protocol->ether_type);
	printf("Ethernet type is :");
	switch(type)
	{
		case ETHERTYPE_IP:printf("IP\n");break;
		case ETHERTYPE_ARP:printf("ARP\n");break;
		case ETHERTYPE_RARP:printf("RARP\n");break;
		case ETHERTYPE_IPV6:printf("IPV6\n");break;
		default:break;
	}
	
	mac = (u_char *)ether_protocol->ether_dhost;
	i = 6;
	printf("Destination Address:");
	do{
		printf("%s%02x",(i==6)?" ":":",*mac++);
	}while(--i>0);
	printf("\n");

	mac = (u_char *)ether_protocol->ether_shost;
	i = 6;
	printf("Source Address:");
	do{
		printf("%s%02x",(i==6)?" ":":",*mac++);
	}while(--i>0);
	printf("\n\n");

	for(i=0;i<pkthdr->len;++i)  
	{  
		printf(" %02x", packet[i]);  
		if((i+1)%16 == 0)  
		{  
			printf("\n");  
		}  
	}  

	printf("\n\n\n");  
	}  
      
int main()  
{  
	char	errBuf[PCAP_ERRBUF_SIZE],* devStr;   

// get a device 
	devStr = pcap_lookupdev(errBuf);  
	if(!devStr)  
	{  
		printf("error: %s\n", errBuf);  
        exit(1);   
	}  
        
// open a device
	pcap_t	*device = pcap_open_live(devStr, 65535, 1, 0, errBuf);  
  	if(!device)  
	{  
		printf("error: pcap_open_live(): %s\n", errBuf);  
		exit(1);  
	}  

// wait loop 
	int	id = 0;  
	pcap_loop(device, -1, getpacket, (u_char*)&id);  

	pcap_close(device);  

	return 0;  
    }  
