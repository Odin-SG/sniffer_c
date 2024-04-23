#ifndef TABLES_SNIFFER
#define TABLES_SNIFFER
#include "types.h"

int find_in_array(const struct arp_table *table, char type, const uint8_t *val, const int pos);
int add_to_table(struct arp_table *table, uint8_t *buf);
void get_system_arp(struct arp_table *table, char const *etherif);

#endif
