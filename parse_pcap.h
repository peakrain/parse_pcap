#ifndef _parse_pcap_h
#define _parse_pcap_h

#include"http_parse.h"
#include<pcap.h>

typedef struct info{
	int src_mac[6];
	int dst_mac[6];
	char src_ip[20];
	char dst_ip[20];
	int src_port;
	int dst_port;
	int protocol;
	int len;
	char rev_time[20];
	int frag;
}information;
int is_frag(int frag);
void parse_eth(const u_char *packe,int len);
void parse_ip(const u_char *packet,int offset,int len);
void parse_tcp(const u_char *packet,int offset,int len);
void parse_udp(const u_char *pakcet,int offset,int len);
void parse_http(const u_char *packet,int offset,int len);
void print();
#endif
