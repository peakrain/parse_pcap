#include"http_parse.h"
#define size 1024
#define max_size 65535
int getLine(char *buf,char **data)
{
	char *p=*data;
	int t_len=strlen(p);
	if(t_len<=0)
		return EOF;
	int ebuf=sscanf(p,"%[^\r\n]",buf);
	if(ebuf==0)
		strcpy(buf,"");
	int len=strlen(buf)+sizeof("\r\n");
	p=p+len-1;
	*data=p;
	return ebuf;
}
void http_analysis(char *data)
{
	char str[size];
	char name[size];
	char value[size];
	char type[10];
	char url[size];
	char version[10];
	char code[10];
	int flag;
	char body[max_size];
	flag=getLine(str,&data);
	if(flag==EOF)
		return;
	while(1)
	{
		if(strncmp(str,"GET",3)==0||strncmp(str,"POST",4)==0)
		{
			sscanf(str,"%s%s",type,url);
			printf("请求头:\n");
			print_info("请求类型",type);
			print_info("url",url);
			while(getLine(str,&data)!=EOF&&
			      sscanf(str,"%s",name)!=EOF)
			{
				sscanf(str,"%[^:]:%[^\n]",name,value);
				print_info(name,value);
			}
			strcpy(body,"");
			while(getLine(str,&data)!=EOF&&
			      sscanf(str,"%s",name)!=EOF)
				{
					strcat(body,str);
					//printf("%0x ",str);
				}		
			if(sscanf(body,"%s",name)!=EOF)
				printf("请求体:%s\n%s",name,body);
			printf("\n");
		}
		else if(strncmp(str,"HTTP",4)==0)
		{
			sscanf(str,"%*[HTTP/]%s%s",version,code);
			printf("响应头:\n");
			print_info("version",version);
			print_info("code",code);
			while(getLine(str,&data)!=EOF&&
			      sscanf(str,"%s",name)!=EOF)
			{
				sscanf(str,"%[^:]:%[^\n]",name,value);
				print_info(name,value);
			}
			strcpy(body,"");
			while(getLine(str,&data)!=EOF&&
			      sscanf(str,"%s",name)!=EOF)
				strcat(body,str);
			if(sscanf(body,"%s",name)!=EOF)
				printf("响应体:\n%02x",body);
				
			printf("\n");
			
		}
		else
		{
			flag=getLine(str,&data);
			if(flag==EOF)
				break;
		}
	}
}
void print_info(char *name,char *value)
{
	printf("字段名:%s 字段值:%s\n",name,value);
}
