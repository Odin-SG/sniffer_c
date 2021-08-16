#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

int main(int argc, char *argv[]) {
    int listenfd = 0, connfd = 0;
    struct sockaddr_in serv_addr;

    char sendBuff[2048];
	int sockopt = 1;

    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    memset(&serv_addr, '0', sizeof(serv_addr));
    memset(sendBuff, 0, sizeof(sendBuff));

	if ((setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(int))) == -1) {
		perror("setsockopt");
		close(listenfd);
		exit(EXIT_FAILURE);
	}

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(5000);

    bind(listenfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    listen(listenfd, 10);

	connfd = accept(listenfd, (struct sockaddr*)NULL, NULL);
    while(read(connfd, sendBuff, sizeof(sendBuff)-1) > 0) {
		printf("%s\n", sendBuff);
		memset(sendBuff, 0, sizeof(sendBuff));
     }
}
