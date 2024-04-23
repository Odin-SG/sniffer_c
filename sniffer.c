#include "sniffer.h"


int sendOp(const int listenfd, uint8_t *sendbuff, uint8_t *rBuf){
	int ret = 0, written = 0, readen = 0;;

	strcpy(&sendbuff[strlen(sendbuff)], " <EOM>");
	written = write(listenfd, sendbuff, strlen(sendbuff));
	printf("%d : ", written);
	if(written <= 0){
		close(listenfd);
		ret = 1;
	}
	readen = read(listenfd, rBuf, RECVBUF);
	if(readen <= 0){
		close(listenfd);
		ret = 1;
	}
	printf("%s\n", rBuf);

	fflush(stdout);
	return ret;
}

void ethListen(const char *ethif, const uint16_t prot, const char *servaddr, uint16_t port){
		uint8_t buf[BUFSIZE], rBuf[RECVBUF];
		char ifName[IFNAMSIZ];
		uint16_t protocol = ETH_P_ALL;
		ssize_t numbytes;
		int currtime;
		struct arp_table table[TABLESIZE];
		int globalDeauth = 0, lastDeauthStamp = 0, globalDhcp = 0, lastDhcpStamp = 0;
		uint32_t transactionID = 0;
		unsigned int timeNextScan = time(NULL);

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
		get_system_arp(table, ethif);

repeat:
		memset(buf, 0, sizeof(buf));
		numbytes = recvfrom(sockfd, buf, BUFSIZE, 0, NULL, NULL);
		currtime = (int)time(NULL);
		memset(sendbuff, 0, sizeof(sendbuff));
		memset(rBuf, 0, sizeof(rBuf));

		if(time(NULL) >= timeNextScan){
			actionDiscover(ethif);
			timeNextScan = time(NULL) + 600;
		}

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

			// dhcp packet
			if(iph->protocol == 0x11){
				if( buf[282] == 0x35 && buf[283] == 0x01){
					switch(buf[284]){
						case 0x01:	sprintf(&sendbuff[strlen(sendbuff)], "DHCP DISCOVER");	break;
						case 0x02:	sprintf(&sendbuff[strlen(sendbuff)], "DHCP OFFER");
							printf("Offer Server:[%d.%d.%d.%d] IP:[%d.%d.%d.%d]\n", buf[58], buf[59], buf[60], buf[61], buf[26], buf[27], buf[28], buf[29]);
							sprintf(&sendbuff[strlen(sendbuff)], "\nClient addr:[%d.%d.%d.%d]\nClient mac:[%02X:%02X:%02X:%02X:%02X:%02X]\nDHCP Server:[%d.%d.%d.%d]\nDHCP Server MAC [%02X:%02X:%02X:%02X:%02X:%02X]",
									buf[58], buf[59], buf[60], buf[61],
									buf[70], buf[71], buf[72], buf[73], buf[74], buf[75],
									buf[26], buf[27], buf[28], buf[29],
									buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);

							break;
						case 0x03:	sprintf(&sendbuff[strlen(sendbuff)], "DHCP REQUEST");	break;
						case 0x04:	sprintf(&sendbuff[strlen(sendbuff)], "DHCP DECLINE");	break;
						case 0x05:	sprintf(&sendbuff[strlen(sendbuff)], "DHCP ACK");
							int btime = time(NULL);
							int newTransactionID = -1;

							newTransactionID = (int)((unsigned char)(buf[46]) << 24 |	(unsigned char)(buf[47]) << 16 | (unsigned char)(buf[48]) << 8 |(unsigned char)(buf[49]));

							/*
							*char *host = NULL;
							*if(htons(edph->len) > 314){
							*	printf("%02X %02X", buf[339], buf[334]);
							*	host = (char*)malloc(((int)buf[339] + (int)buf[334])+1);
							*	memcpy(host, &buf[340], (int)buf[339]);
							*	sprintf(&host[strlen(host)], ".");
							*	memcpy(&host[strlen(host)], &buf[335], (int)buf[334]);
							*}
							*/
							if((btime - lastDhcpStamp) <= 6 ){
								if((transactionID != newTransactionID))
									globalDhcp ++;
								else
									globalDhcp = globalDhcp;
							} else {
								globalDhcp = 0;
 							}
 							printf("ACK [%d] [%d]\n", globalDhcp, transactionID);
							sprintf(&sendbuff[strlen(sendbuff)], "\nClient addr:[%d.%d.%d.%d]\nClient mac:[%02X:%02X:%02X:%02X:%02X:%02X]\nDHCP Server:[%d.%d.%d.%d]\nDHCP Server MAC [%02X:%02X:%02X:%02X:%02X:%02X]",
									buf[58], buf[59], buf[60], buf[61],
									buf[70], buf[71], buf[72], buf[73], buf[74], buf[75],
									buf[26], buf[27], buf[28], buf[29],
									buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]);
							if(globalDhcp >= 3){
								sprintf(&sendbuff[strlen(sendbuff)], "\nDHCP starvation ATTACK [attempt:(%d), betweentime(%d)]",
										globalDhcp,
										(btime - lastDhcpStamp));
							}
							transactionID = newTransactionID;
							lastDhcpStamp = time(NULL);
							break;
						case 0x06:	sprintf(&sendbuff[strlen(sendbuff)], "DHCP NACK");	break;
						case 0x07:	sprintf(&sendbuff[strlen(sendbuff)], "DHCP RELEASE");	break;
						case 0x08:	sprintf(&sendbuff[strlen(sendbuff)], "DHCP INFORM");	break;
					}
					sprintf(&sendbuff[strlen(sendbuff)], "\n");
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
			printf("./sniffer [interface name (aka enp37s0)] [hex protocol (0806) or (1) for all] [server ip (aka 192.168.0.2)] [port (aka 3000)]\n");
		return 0;
}
