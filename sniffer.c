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
#include <sys/signal.h>

#define BUFSIZE 2048
#define DEFAULTIF "enp37s0"
#define MAXLINE 16
#define TABLESIZE 1024
#define MACSIZE 6
#define IPSIZE 4
#define RECVBUF 64

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
		sprintf(&retBuff[cb++], "\n <EOM>");
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

int find_in_array(const struct arp_table *table, char type, const uint8_t *val, const int pos){
	int cointcid;
	for(int step = 0; step < point; step++){
		uint8_t isFail = 0;
		if(val[0] == 0xDE && val[1] == 0xAD){
			int a = 1;
		}
		switch(type){
			case 'i':
				for(int i = 0; i < IPSIZE; i++){
					if(table[step].ip[i] != val[i])
						isFail = 1;
				}
				if(isFail == 0)
					return step;
				break;
			case 'm':
				for(int i = 0; i < MACSIZE; i++){
					if(table[pos].mac[i] != val[i])
						isFail = 1;
				}
				if(isFail == 0)
					return pos;
				else
					return -1;
				break;
			default:
				return -1;
		}
	}
	return -1;
}

int add_to_table(struct arp_table *table, uint8_t *buf){
	int bufpoint, currpoint, err, attack = 0;
	currpoint = point;

	if((err = find_in_array(table, 'i',  &buf[28], 0)) != -1){
		if(find_in_array(table, 'm', &buf[22], err) == -1)
			attack = 1;
		currpoint = err;
	} else {
		point++;
	}

	for(bufpoint = 0; bufpoint < IPSIZE; bufpoint++){
			table[currpoint].ip[bufpoint] = buf[28 + bufpoint];
	}
	for(bufpoint = 0; bufpoint < MACSIZE; bufpoint++){
			table[currpoint].mac[bufpoint] = buf[22 + bufpoint];
	}
	return attack;
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
		//strcpy(&retBuff[strlen(retBuff)], " <EOM>");
	}
}

int sendOp(const int listenfd, uint8_t *sendbuff, uint8_t *rBuf){
	int ret = 0, written = 0, readen = 0;;

	strcpy(&sendbuff[strlen(sendbuff)], " <EOM>");
	written = write(listenfd, sendbuff, strlen(sendbuff));
	printf("%d\n", written);
	if(written <= 0){
		close(listenfd);
		ret = 1;
	}
	readen = read(listenfd, rBuf, RECVBUF);
	if(readen <= 0){
		close(listenfd);
		ret = 1;
	}
	return ret;
}

void ethListen(const char *ethif, const uint16_t prot, const char *servaddr, uint16_t port){
		uint8_t buf[BUFSIZE], rBuf[RECVBUF];
		char ifName[IFNAMSIZ];
		uint16_t protocol = ETH_P_ALL;
		ssize_t numbytes;
		int currtime;
		struct arp_table table[TABLESIZE];
		int globalDeauth = 0, lastDeauthStamp = 0;

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

conne:
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

		signal(SIGPIPE, SIG_IGN);

		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		if(inet_pton(AF_INET, servaddr, &addr.sin_addr) <= 0){
			perror("inet_pton");
			close(listenfd);
			exit(EXIT_FAILURE);
		}
		while (connect(listenfd, (struct sockaddr*) &addr, sizeof(addr)) < 0){
			perror("connect");
			sleep(5);
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
				//dump(sendbuff, numbytes, NULL);
				if (buf[27] == 0x00 && buf[26] == 0xc0){
					sprintf(sendbuff, "[%d] type[1], mac[%02X %02X %02X %02X %02X %02X]\n", (int)time(NULL), buf[30], buf[31], buf[32], buf[33], buf[34], buf[35]);
				} else if(buf[4] == 0x04 && buf[5] == 0x80 && buf[6] == 0x02 && buf[7] == 0x00) {
 					sprintf(sendbuff, "[%d] type[2], mac[%02X %02X %02X %02X %02X %02X]\n", (int)time(NULL), buf[17], buf[18], buf[19], buf[20], buf[21], buf[22]);
				}

				strcpy(&sendbuff[strlen(sendbuff)], "Deauth!");
				if((time(NULL) - lastDeauthStamp) <= 2){
					lastDeauthStamp = time(NULL);
					globalDeauth++;
				} else {
					globalDeauth = 0;
				}

				if(globalDeauth >= 3){
					strcpy(&sendbuff[strlen(sendbuff)], " Attack!");
				}
				lastDeauthStamp = time(NULL);
				if(sendOp(listenfd, sendbuff, rBuf)){
					goto conne;
				}
			}
			// arp packet
			if(htons(eh->ether_type) == 0x0806){
				//dump(buf, numbytes, NULL);
				if(buf[21] == 2){
					arp_dump(buf, currtime, eh, sendbuff);
					if(add_to_table(table, buf)){
						sprintf(&sendbuff[strlen(sendbuff)], "Inced: Arp spoofing attack is detected\n");
					}
					if(sendOp(listenfd, sendbuff, rBuf)){
						goto conne;
					}
				}
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
