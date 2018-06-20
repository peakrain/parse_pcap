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
char *time_format="%Y-%m-%d %H:%M:%S";
information *info;
char *format_time(char *format,time_t time);
int is_frag(int frag)
{
	int i,flag;
	for(i=0;i<6;i++)
		frag=frag/2;
	flag=frag%2;
	frag=flag==1||frag==0;
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
int is_http(char *data)
{
	char str[1024];
	sscanf(data,"%s",str);
	if(strncmp(str,"GET",3)==0||
	   strncmp(str,"POST",4)==0||
	   strncmp(str,"HTTP",4)==0)
			return 1;
	else
		return 0;
	
}
void print_0x(const u_char *data,int len)
{
	int i;
	for(i=0;i<len;i++)
	{
		if(i%16==0)
			printf("%d: ",i/16);
		printf("%02x ",data[i]);
		if((i+1)%8==0)
			printf(" ");
		if((i+1)%16==0)
			printf("\n");
	}
	printf("\n");
}
void parse_http(const u_char *packet,int offset,int len)
{
	printf("offset:%d len:%d packetlen:%d\n",offset,len,strlen(packet));
	char *data=(char *)(packet+offset);
//	if(is_http(data))
	{
		printf("offset:%d len:%d datalen:%d\n",offset,len,strlen(data));
		print();
		print_0x(packet,len);
		//http_analysis(data);
		/*int length=len-offset;
		int i;
		for(i=0;i<length;i++)
		{
			printf("%c",data[i]);
			if((i+1)%16==0);
			//	printf("\n");
		}
		printf("\n");*/
	}
}
void print()
{
	int i;
	/*printf("Src_Mac: ");
	for(i=0;i<ETH_ALEN-1;i++)
		printf("%0x:",info->src_mac[i]);
	printf("%0x ",info->src_mac[ETH_ALEN-1]);
	printf("Dst_Mac: ");
	for(i=0;i<ETH_ALEN-1;i++)
		printf("%0x:",info->dst_mac[i]);
	printf("%0x ",info->dst_mac[ETH_ALEN-1]);**/
	printf("Src_IP: %s ",info->src_ip);
	printf("Dst_IP: %s \n",info->dst_ip);
	printf("Src_Port: %d ",info->src_port);
	printf("Dst_Port: %d ",info->dst_port);
	printf("Protocol: %d ",info->protocol);
	printf("Frag: %d ",info->frag);
	printf("Length: %d\n",info->len);
	printf("Rev_Time: %s\n",info->rev_time);	
	
}
void call_back(u_char *user,const struct pcap_pkthdr *pkthdr,const u_char *packet)
{
	int *id=(int *)user;
	int offset=0;
	printf("%d:len:%d caplen:%d\n",++(*id),pkthdr->len,pkthdr->caplen);
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
