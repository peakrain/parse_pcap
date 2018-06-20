#include<stdio.h>
#include<string.h>
#include<malloc.h>
int getLine(char *buf,char **data);
int main()
{
	char *data="GET test.png HTTP/1.1\r\nHost:http://hwdong/com\r\n";
	char str[1024];
	int flag;
	int i;
	for(i=0;i<10;i++)
	if(getLine(str,&data)!=EOF)
	{
		printf("%s\n",str);
	}
	else
		break;
	return 0;
}
int getLine(char *buf,char **data)
{
	char *p=*data;
	int t_len=strlen(p);
	if(t_len<=0)
		return EOF;
	sscanf(p,"%[^\r\n]",buf);
	int len=strlen(buf)+sizeof("\r\n");
	p=p+len-1;
	*data=p;
	return 0;
}
