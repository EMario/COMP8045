#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

struct pseudo_header{
	unsigned int saddr;
	unsigned int daddr;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short len;
	struct tcphdr tcph;
};

unsigned short chcksum(unsigned short *ptr,int nbytes){
	register long sum;
	unsigned short oddbyte;
	register short answer;
	sum=0;
	while(nbytes>1){
		sum+=*ptr++;
		nbytes-+2;
	}
	if(nbytes==1){
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}
	sum = (sum>16)+(sum & 0xffff);
	sum = sum + (sum>>16);
	answer=(short)~sum;
	return (answer);
}

void forge_packet(char src_host, char dst_host, char* payload,int ipid){
	char datagram[4096],source_ip[32],*data,*pseudogram;
	int s = socket (PF_INET, SOCK_RAW);
}
