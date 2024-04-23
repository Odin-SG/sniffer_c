#ifndef DUMP_SNIFFER
#define DUMP_SNIFFER
#include "types.h"

void dump (const uint8_t *buf, ssize_t numbytes, uint8_t *retBuff);
void arp_dump(const uint8_t *buf, int currtime, struct ether_header *eh, uint8_t *retBuff);

#endif
