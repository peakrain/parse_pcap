#include"parse_pcap.h"
#include<stdio.h>
#include<time.h>
#include<linux/ip.h>
#include<linux/tcp.h>
#include<linux/udp.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include<malloc.h>
#include<string.h>
information *info;
char *format_time(char *format,time_t time);
int is_frag(int frag)
{
	int i,flag;
	for(i=0;i<6;i++)
		frag=frag/2;
	flag=frag%2;
	return flag;
}
void parse_eth(const u_char *packet,int len)
{
	struct ethhdr* eth;
	int eth_len=sizeof(struct ethhdr);
	int i;
	eth=(struct ethhdr*)packet;
	for(i=0;i<ETH_ALEN;i++){
		info->src_mac[i]=eth->h_source[i];
		info->dst_mac[i]=eth->h_dest[i];
	}
	parse_ip(packet,eth_len,len);
}
void parse_ip(const u_char *packet,int offset,int len)
{
	if(len>offset)
	{
		struct in_addr addr;
		struct iphdr* ip_h;
		ip_h=(struct iphdr*)(packet+offset);
		addr.s_addr=ip_h->saddr;
		strcpy(info->src_ip,inet_ntoa(addr));
		addr.s_addr=ip_h->daddr;
		strcpy(info->dst_ip,inet_ntoa(addr));
		info->protocol=ip_h->protocol;
		int frag=(int)ip_h->frag_off;
		info->frag=is_frag(frag);
		offset+=sizeof(struct iphdr);
		if(ip_h->protocol==6)
			parse_tcp(packet,offset,len);
		else if(ip_h->protocol==17)
			parse_udp(packet,offset,len);	
	}
	else
	{
		printf("packet length error!\n");
		return;
	}
}
void parse_tcp(const u_char *packet,int offset,int len)
{
	struct tcphdr *tcp_h;
	tcp_h=(struct tcphdr*)(packet+offset);
	offset+=sizeof(struct tcphdr);
	info->src_port=ntohs(tcp_h->source);
	info->dst_port=ntohs(tcp_h->dest);
	parse_http(packet,offset,len);
}
void parse_udp(const u_char *packet,int offset,int len)
{
	struct udphdr *udp_h;
	udp_h=(struct udphdr*)(packet+offset);
	offset+=sizeof(struct udphdr);
	info->src_port=ntohs(udp_h->source);
	info->dst_port=ntohs(udp_h->dest);
}
void parse_http(const u_char *packet,int offset,int len)
{
	print_info();
	/*char *data=(char *)(packet+offset);
	int length=len-offset;
	int i;
	for(i=0;i<length;i++)
		printf("%c",data[i]);
	printf("\n");*/
}
void print_info()
{
	int i;
	printf("Src_Mac: ");
	for(i=0;i<ETH_ALEN-1;i++)
		printf("%0x:",info->src_mac[i]);
	printf("%0x ",info->src_mac[ETH_ALEN-1]);
	printf("Dst_Mac: ");
	for(i=0;i<ETH_ALEN-1;i++)
		printf("%0x:",info->dst_mac[i]);
	printf("%0x ",info->dst_mac[ETH_ALEN-1]);
	printf("Src_IP: %s ",info->src_ip);
	printf("Dst_IP: %s ",info->dst_ip);
	printf("Src_Port: %d ",info->src_port);
	printf("Dst_Port: %d ",info->dst_port);
	printf("Protocol: %d\n",info->protocol);
	printf("Rev_Time: %s\n",info->rev_time);	
	
}
void call_back(u_char *user,const struct pcap_pkthdr *pkthdr,const u_char *packet)
{
	int *id=(int *)user;
	int offset=0;
	printf("%d:",++(*id));
	//analysis pcap_header
	info->len=pkthdr->len;
	char *time=format_time(time_format,(time_t)pkthdr->ts.tv_sec);
	strcpy(info->rev_time,time);
	parse_eth(packet,pkthdr->len);
}
char *format_time(char *format,time_t time)
{	
	struct tm *timeptr=localtime(&time);
	char timestr[20];
	strftime(timestr,sizeof(timestr),format,timeptr);
	char *ltime=(char *)malloc(sizeof(char));
	strcpy(ltime,timestr);
	return ltime;
} 
void analysis(int num,char *buf,char *filename)
{
	info =(information*)malloc(sizeof(information));
	char ebuf[PCAP_ERRBUF_SIZE];
	/*open a pcap file*/
	pcap_t *device=pcap_open_offline(filename,ebuf);
	if(!device)
	{
		printf("error:%s\n",ebuf);
		return;
	}
	/*catch pakcet*/
	int i=0;
	struct bpf_program fp;
	pcap_compile(device,&fp,buf,1,0);
	pcap_setfilter(device,&fp);
	pcap_loop(device,num,call_back,(u_char*)&i);
	pcap_close(device);
	
}
int main(int argc,char *argv[])
{
	if(argc!=2)
	{
		printf("syntax error!\n");
		return;
	}
	char *filename=argv[1];
	analysis(-1,"tcp",filename);
	return 0;
}
