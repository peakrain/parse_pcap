OBJ=main.o parse_pcap.o http_parse.o
GOBJ=main.c parse_pcap.c http_parse.c
LIB=pcap
main:${OBJ}
	gcc -o main ${OBJ} -l ${LIB}
clean:
	rm -f *.o main
gdb:
	gcc -g -o main ${GOBJ} -l ${LIB}
