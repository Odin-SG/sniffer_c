#ifndef DHCP_SNIFFER
#define DHCP_SNIFFER
#include "types.h"

struct addrs {
	int *sock;
	struct sockaddr_in sockaddr;
};

struct addrs* openSocket(const char* iface);
int actionDiscover(const char* iface);
void buildPacket(char *dhreq);

#endif

