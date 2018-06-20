#include"parse_pcap.h"
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
