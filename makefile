OBJ=parse_pcap.o
LIB=pcap
main:${OBJ}
	gcc -o main ${OBJ} -l ${LIB}
clean:
	rm -f *.o
