#include "dhcpdiscover.h"
#define PORT 67
#define SRCPORT 68
#define DHCPSIZE 244

struct addrs server_host;

struct addrs* openSocket(const char* iface){
	int sockf;
	struct sockaddr_in server_ht, srcaddr;
	int n, len;
	int brcst = 1, reuse = 1;
	char  ifName[IFNAMSIZ];
	char *ip = "0.0.0.0";

	memset(&server_ht, 0, sizeof(server_ht));
	strcpy(ifName, iface);
	server_ht.sin_port = htons(PORT);
	server_ht.sin_family = AF_INET;
	server_ht.sin_addr.s_addr = INADDR_BROADCAST;

	memset(&srcaddr, 0, sizeof(srcaddr));
	srcaddr.sin_port = htons(SRCPORT);
	srcaddr.sin_family = AF_INET;
	srcaddr.sin_addr.s_addr = inet_addr(ip);

	if((sockf = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("socket");
		exit(EXIT_FAILURE);
	}
	if((setsockopt(sockf, SOL_SOCKET, SO_BROADCAST, &brcst, sizeof(brcst))) < 0){
		perror("setsockopt");
		close(sockf);
		exit(EXIT_FAILURE);
	}
	if((setsockopt(sockf, SOL_SOCKET, SO_BINDTODEVICE, ifName, IFNAMSIZ)) < 0){
		perror("bind to device");
		close(sockf);
		exit(EXIT_FAILURE);
	}
	if((setsockopt(sockf, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse))) < 0){
		perror("reuseaddr");
		close(sockf);
		exit(EXIT_FAILURE);
	}
	if((bind(sockf, (struct sockaddr *) &srcaddr, sizeof(srcaddr))) < 0){
		perror("bind");
		close(sockf);
		exit(EXIT_FAILURE);
	}
	server_host.sock = &sockf;
	server_host.sockaddr = server_ht;
	return &server_host;
}

void buildPacket(char *dhreq){
	memset(dhreq, 0, sizeof(dhreq));
	// pos-42
	dhreq[0] = 0x01 /*Mes type*/; dhreq[1] = 0x01/*HW type*/; dhreq[2] = 0x06/*HW addr length*/;
	dhreq[4] = 0x77; dhreq[5] = 0xC9; dhreq[6] = 0xD7; dhreq[7] = 0x15; //Transaction ID;
	dhreq[28] = 0x00; dhreq[29] = 0xC0; dhreq[30] = 0xC1;  dhreq[31] = 0xC2; dhreq[32] = 0xC3; dhreq[33] = 0xC4; //Client mac addr
	dhreq[236] = 0x63; dhreq[237] = 0x82; dhreq[238] = 0x53; dhreq[239] = 0x63; //Magic cookie
	dhreq[240] = 0x35; dhreq[241] = 0x01; dhreq[242] = 0x01; //Option 53 Discover
	dhreq[243] = 0xFF; // End
}

int actionDiscover(const char* iface){
	char buf[DHCPSIZE];
	struct addrs *server_host = openSocket(iface);
	int siz;
	memset(buf, 0, sizeof(buf));
	buildPacket(buf);
	siz = sendto(*server_host->sock, buf, sizeof(buf), 0, (struct sockaddr *)&server_host->sockaddr, sizeof(server_host->sockaddr));
	printf("DHCP Discover sent\n");

	close(*server_host->sock);
}

