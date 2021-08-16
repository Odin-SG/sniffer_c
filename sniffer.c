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

void dump (const uint8_t *buf, ssize_t numbytes, uint8_t *retBuff) {
	int i, l, n ,cb = 0;

	n = 0;
	if(retBuff != NULL){
		for (i = 0; i < numbytes;){
			for(l = 0; l < MAXLINE; l++){
				if((l % ((MAXLINE) / 2)) == 0)
					sprintf(&retBuff[cb++], " ");
				sprintf(&retBuff[cb], "%02x ", buf[i]); cb += 3;
				i++;
			}
			sprintf(&retBuff[cb], "   "); cb += 3;
			for(l = i - MAXLINE; l < (MAXLINE + i); l++){
				if((int)buf[l] > 31 && (int)buf[l] < 127)
					sprintf(&retBuff[cb++], "%1c", buf[l]);
				else
					sprintf(&retBuff[cb++], "%1c", '.');
			}
			sprintf(&retBuff[cb++], "\n");
		}
		sprintf(&retBuff[cb++], "\n");
		fflush(stdout);
	} else {
		for (i = 0; i < numbytes;){
			for(l = 0; l < MAXLINE; l++){
				if((l % ((MAXLINE) / 2)) == 0)
					printf(" ");
				printf ("%02x ", buf[i]);
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
				return step;
			case 'm':
				for(int i = 0; i < MACSIZE; i++){
					if(table[step].mac[i] != val[i])
						return -1;
				}
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
		if(find_in_array(table, 'm', &buf[32]) == -1)
			printf("Attack! This ip is trying to bind to this mac! Position on table %d\n", err);
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

void arp_dump(const uint8_t *buf, int currtime, struct ether_header *eh, uint8_t *retBuff){
	if(retBuff == NULL){
		printf("[%d] protocol:%04X type:%02X\n", currtime, htons(eh->ether_type), buf[21]);
		printf("Sender Mac: [%02X.%02X.%02X.%02X.%02X.%02X]\n", buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]);
		printf("Sender IP: [%d.%d.%d.%d]\n", buf[28], buf[29], buf[30], buf[31]);
		printf("Target Mac: [%02X.%02X.%02X.%02X.%02X.%02X]\n", buf[32], buf[33], buf[34], buf[35], buf[36], buf[37]);
		printf("Target IP: [%d.%d.%d.%d]\n", buf[38], buf[39], buf[40], buf[41]);
	} else {
		sprintf(&retBuff[strlen(retBuff)], "[%d] protocol:%04X type:%02X\n", currtime, htons(eh->ether_type), buf[21]);
		sprintf(&retBuff[strlen(retBuff)], "Sender Mac: [%02X.%02X.%02X.%02X.%02X.%02X]\n", buf[22], buf[23], buf[24], buf[25], buf[26], buf[27]);
		sprintf(&retBuff[strlen(retBuff)], "Sender IP: [%d.%d.%d.%d]\n", buf[28], buf[29], buf[30], buf[31]);
		sprintf(&retBuff[strlen(retBuff)], "Target Mac: [%02X.%02X.%02X.%02X.%02X.%02X]\n", buf[32], buf[33], buf[34], buf[35], buf[36], buf[37]);
		sprintf(&retBuff[strlen(retBuff)], "Target IP: [%d.%d.%d.%d]\n", buf[38], buf[39], buf[40], buf[41]);
	}
}

void ethListen(const char *ethif, const uint16_t prot, const char *servaddr, uint16_t port){
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

		struct sockaddr_in addr;
		int listenfd = 0;
		char sendbuff[BUFSIZE];

		struct ifreq ifopts;
		struct ifreq if_ip;
		struct sockaddr_storage their_addr;

		int sockfd, sockserver, res;
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

		if ((res = setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ)) == -1){
			perror("SO_BINDTODEVICE");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		if((listenfd = socket(AF_INET, SOCK_STREAM, 0)) == -1){
			perror("LISTENSOCK");
			close(listenfd);
			exit(EXIT_FAILURE);
		}

		if((setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int))) == -1){
			perror("LISTENREUSE");
			close(listenfd);
			exit(EXIT_FAILURE);
		}
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		if(inet_pton(AF_INET, servaddr, &addr.sin_addr) <= 0){
			perror("inet_pton");
			close(listenfd);
			exit(EXIT_FAILURE);
		}

		if (connect(listenfd, (struct sockaddr*) &addr, sizeof(addr)) < 0){
			perror("connect");
			close(listenfd);
			exit(EXIT_FAILURE);
		}

repeat:
		memset(buf, 0, sizeof(buf));
		numbytes = recvfrom(sockfd, buf, BUFSIZE, 0, NULL, NULL);
		currtime = (int)time(NULL);
		memset(sendbuff, 0, sizeof(sendbuff));

		// Type param 1 capture all packet (arp and deuath)
		if(prot == 1){
			// deauth packet
			if((buf[4] == 0x04 && buf[5] == 0x80 && buf[6] == 0x02 && buf[7] == 0x00) || (buf[27] == 0x00 && buf[26] == 0xc0)){
				printf("%02X %02X %02X %02X / %02X %02X\n", buf[4], buf[5], buf[6], buf[7], buf[25], buf[26]);
				dump(sendbuff, numbytes, NULL);
				strcpy(sendbuff, "Deauth!");
				write(listenfd, sendbuff, strlen(sendbuff));
			}
			// arp packet
			if(htons(eh->ether_type) == 0x0806){
				dump(buf, numbytes, NULL);
				arp_dump(buf, currtime, eh, sendbuff);
				write(listenfd, sendbuff, strlen(sendbuff));
				if(buf[21] == 2)
					add_to_table(table, buf);
			}
			fflush(stdout);

			// All packet
			//dump(buf, numbytes, sendbuff);
			//write(listenfd, sendbuff, strlen(sendbuff));
		} else if(htons(eh->ether_type) == protocol){
			if(htons(eh->ether_type) == 0x0806){
				arp_dump(buf, currtime, eh, sendbuff);
				if(buf[21] == 2)
					add_to_table(table, buf);
			} else
				printf("[%d] protocol:%04X\n", currtime, htons(eh->ether_type));
			dump(buf, numbytes, sendbuff);
		}
		goto repeat;
}

int main(int argc, char **argv, char **envp){
		char *etherif = NULL;
		uint16_t protocol = 0, port = 0;
		const char *servaddr;
		point = 0;
		if(argc == 5){
			if(argv[1])
				etherif = argv[1];
			if(argv[2])
				protocol = (uint16_t) strtol(argv[2], NULL, 16);
			if(argv[3])
				servaddr = argv[3];
			if(argv[4])
				port = (uint16_t) strtol(argv[4], NULL, 10);
			ethListen(etherif, protocol, servaddr, port);
		}
		if(argc < 5)
			printf("./sniffer [interface name (aka enp37s0)] [hex protocol (0806)] [server ip (aka 192.168.0.2)] [port (aka 3000)]\n");
		return 0;
}
