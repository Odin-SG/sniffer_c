#ifndef TYPES_SNIFFER
#define TYPES_SNIFFER

#include <arpa/inet.h>
//#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <unistd.h>
//#include <sys/signal.h>
#include <signal.h>
#include "dump.h"

#define BUFSIZE 2048
#define DEFAULTIF "enp37s0"
#define MAXLINE 16
#define TABLESIZE 1024
#define MACSIZE 6
#define IPSIZE 4
#define RECVBUF 128

struct arp_table {
	uint8_t ip[IPSIZE];
	uint8_t mac[MACSIZE];
};

static int point; // Показывает, сколько записей в struct arp_table table[BUFSIZE]

#endif
