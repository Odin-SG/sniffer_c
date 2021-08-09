#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define BUFSIZE 1024
#define DEFAULTIF "enp37s0"
#define MAXLINE 16

void ethListen(){
		uint8_t buf[BUFSIZE];
		char ifName[IFNAMSIZ] = DEFAULTIF;
		ssize_t numbytes;

		struct ifreq ifopts;
		struct ifreq if_ip;
		struct sockaddr_storage their_addr;

		int sockfd, ret, i, l, n;
		int sockopt = 1;
		struct ether_header *eh = (struct ether_header*) buf;
		struct iphdr *iph = (struct iphdr*) (buf + sizeof(struct ether_header));
		struct udbhdr *edph = (struct udphdr*) (buf + sizeof(struct iphdr) + sizeof(struct ether_header));

		if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(0x0800))) == -1){
			perror("listener: socket");
			close(sockfd);
			exit(EXIT_FAILURE);
		}

		int res;

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

		n = 0;
repeat:
		numbytes = recvfrom(sockfd, buf, BUFSIZE, 0, NULL, NULL);

		printf("\tData:\n");
		for (i = 0; i < numbytes;){
			for(l = 0; l < MAXLINE; l++){
				printf("%02x ", buf[i]);
				i++;
			}
			printf("   ");
			for(l = i - MAXLINE; l < (MAXLINE + i); l++){
				if((int)buf[l] > 31)
					printf("%1c ", buf[l]);
				else
					printf("%1c", '.');
			}
			printf("\n");
		}
		printf("\n");
		fflush(stdout);
		goto repeat;
}

int main(int argc, char **argv){
        ethListen();
}
