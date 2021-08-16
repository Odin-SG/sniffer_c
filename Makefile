all: sniffer.c server
	gcc -g3 sniffer.c -o sniffer

server: server.c
	gcc -g3 server.c -o server
#sniffer: sniffer.c
#	mips-linux-gnu-gcc-10 -static -static-libgcc -pipe -mno-branch-likely -mips32r2 -mtune=24kc -march=24kc sniffer.c -o sniffer
