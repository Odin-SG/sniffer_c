#include "dump.h"

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
