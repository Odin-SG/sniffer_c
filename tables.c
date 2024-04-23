#include "tables.h"

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

int find_in_array(const struct arp_table *table, char type, const uint8_t *val, const int pos){
	int cointcid;
	for(int step = 0; step < point; step++){
		uint8_t isFail = 0;

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

void mac_to_bytes(const char *mac_str, uint8_t *mac) {
    int values[MACSIZE];
    sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]);
    for (int i = 0; i < MACSIZE; ++i) {
        mac[i] = (uint8_t)values[i];
    }
}

int is_zero_mac(uint8_t *mac) {
    for (int i = 0; i < MACSIZE; ++i) {
        if (mac[i] != 0) {
            return 0;
        }
    }
    return 1;
}

void get_system_arp(struct arp_table *table, char const *etherif) {
    FILE *fp;
    char line[256];
    int count = 0;
	//char *TEMPETHIF = "br-lan";

    //fp = popen("arp -a", "r");
	fp = popen("cat /proc/net/arp", "r");
    if (fp == NULL) {
        perror("popen");
        exit(1);
    }

    fgets(line, sizeof(line), fp);  // Тут пропускаем первую линию с описанием

    while (fgets(line, sizeof(line), fp) != NULL) {
        char ip_str[INET_ADDRSTRLEN], mac_str[18], dev[10];
        sscanf(line, "%s %*s %*s %s %*s %s", ip_str, mac_str, dev);

        if (strcmp(dev, etherif) == 0) {
            uint8_t temp_mac[MACSIZE];
            mac_to_bytes(mac_str, temp_mac);

            if (!is_zero_mac(temp_mac)) {
                inet_pton(AF_INET, ip_str, table[count].ip);
                memcpy(table[count].mac, temp_mac, MACSIZE);
                count++;
				point++;
            }
        }
    }


    pclose(fp);

    for (int i = 0; i < count; ++i) {
        printf("IP: ");
        for (int j = 0; j < IPSIZE; ++j) {
            printf("%02X ", table[i].ip[j]);
        }
        printf(", MAC: ");
        for (int j = 0; j < MACSIZE; ++j) {
            printf("%02X ", table[i].mac[j]);
        }
        printf("\n");
    }

}
