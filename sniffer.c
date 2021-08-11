#include <arpa/inet.h>
//#include <linux/if_packet.h>
#include <linux/ip.h>
//#include <linux/udp.h>
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

#define BUFSIZE 2048
#define DEFAULTIF "enp37s0"
#define MAXLINE 16
#define TABLESIZE 1024
#define MACSIZE 6
#define IPSIZE 4

struct arp_table {
	uint8_t ip[IPSIZE];
	uint8_t mac[MACSIZE];
};

static int point;

void dump (uint8_t *buf, ssize_t numbytes) {
	int i, l, n;

	n = 0;
	for (i = 0; i < numbytes;){
		for(l = 0; l < MAXLINE; l++){
			if((l % ((MAXLINE) / 2)) == 0)
				printf(" ");
			printf("%02x ", buf[i]);
			i++;
		}
		printf("   ");
		for(l = i - MAXLINE; l < (MAXLINE + i); l++){
			if((int)buf[l] > 31 && (int)buf[l] < 127)
				printf("%1c", buf[l]);
			else
				printf("%1c", '.');
		}
		printf("\n");
	}
	printf("\n");
	fflush(stdout);
}

int find_in_array(const struct arp_table *table, char type, const uint8_t *val){
	int cointcid;
	for(int step = 0; step < point; step++){
		switch(type){
			case 'i':
				for(int i = 0; i < IPSIZE; i++){
					if(table[step].ip[i] != val[i])
						return -1;
				}
				printf("Attack! This ip is trying to bind to this mac! Position on table %d\n", step);
				return step;
			case 'm':
				for(int i = 0; i < MACSIZE; i++){
					if(table[step].mac[i] != val[i])
						return -1;
				}
				printf("Attack! This mac is trying to bind to this ip! Position on table %d\n", step);
				return step;
			default:
				return -1;
		}
	}
	return -1;
}

void add_to_table(struct arp_table *table, uint8_t *buf){
	int bufpoint, currpoint, err;
	currpoint = point;

	if((err = find_in_array(table, 'i',  &buf[38])) != -1){
		currpoint = err;
	}

	for(bufpoint = 0; bufpoint < IPSIZE; bufpoint++){
			table[currpoint].ip[bufpoint] = buf[38 + bufpoint];
	}
	for(bufpoint = 0; bufpoint < MACSIZE; bufpoint++){
			table[currpoint].mac[bufpoint] = buf[32 + bufpoint];
	}
	point++;
}

void ethListen(const char *ethif, const uint16_t prot){
		uint8_t buf[BUFSIZE];
		char ifName[IFNAMSIZ];
		uint16_t protocol = ETH_P_ALL;
		ssize_t numbytes;
		int currtime;
		struct arp_table table[TABLESIZE];

		if(ethif)
			strcpy(ifName, ethif);
		else
			strcpy(ifName, DEFAULTIF);
		if(prot)
			protocol = prot;

		struct ifreq ifopts;
		struct ifreq if_ip;
		struct sockaddr_storage their_addr;

		int sockfd, res;
		int sockopt = 1;
		struct ether_header *eh = (struct ether_header*) buf;
		struct iphdr *iph = (struct iphdr*) (buf + sizeof(struct ether_header));
		struct udphdr *edph = (struct udphdr*) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

		if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1){
			perror("listener: socket");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		if ((res = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int))) == -1) {
			perror("setsockopt");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
		ioctl(sockfd, SIOCGIFFLAGS, &ifopts);
		ifopts.ifr_flags |= IFF_PROMISC;
		ioctl(sockfd, SIOCSIFFLAGS, &ifopts);

		if ((res = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ)) == -1)	{
			perror("SO_BINDTODEVICE");
			close(sockfd);
			exit(EXIT_FAILURE);
		}
repeat:
		numbytes = recvfrom(sockfd, buf, BUFSIZE, 0, NULL, NULL);
		currtime = (int)time(NULL);

		if(htons(eh->ether_type) == protocol){
			if(htons(eh->ether_type) == 0x0806){
				printf("[%d] protocol:%04X type:%02X\n", currtime, htons(eh->ether_type), buf[21]);
				printf("Sender Mac: [%02X.%02X.%02X.%02X.%02X.%02X]\n", buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]);
				printf("Sender IP: [%d.%d.%d.%d]\n", buf[28], buf[29], buf[30], buf[31]);
				printf("Target Mac: [%02X.%02X.%02X.%02X.%02X.%02X]\n", buf[32], buf[33], buf[34], buf[35], buf[36], buf[37]);
				printf("Target IP: [%d.%d.%d.%d]\n", buf[38], buf[39], buf[40], buf[41]);
				if(buf[21] == 2)
					add_to_table(table, buf);
			} else
				printf("[%d] protocol:%04X\n", currtime, htons(eh->ether_type));
			dump(buf, numbytes);
		}
		goto repeat;
}

int main(int argc, char **argv, char **envp){
		char *etherif = NULL;
		uint16_t protocol = 0;
		point = 0;
		if(argc == 3){
			if(argc && argv[1])
				etherif = argv[1];
			if(argv[2])
				protocol = (uint16_t) strtol(argv[2], NULL, 16);
			ethListen(etherif, protocol);
		}
		if(argc < 3)
			printf("./sniffer [interface name (aka enp37s0)] [hex protocol (0806)]\n");
		return 0;
}
