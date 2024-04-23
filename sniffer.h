#ifndef MAIN_SNIFFER
#define MAIN_SNIFFER
#include "types.h"
#include "dump.h"
#include "tables.h"
#include "dhcpdiscover.h"

int sendOp(const int listenfd, uint8_t *sendbuff, uint8_t *rBuf);
void ethListen(const char *ethif, const uint16_t prot, const char *servaddr, uint16_t port);

#endif
