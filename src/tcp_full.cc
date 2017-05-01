// tcp_full.cpp

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "tcp_full.h"

void tcp_full::action(const char* host, int port) {
	srandom(time(NULL));

	struct hostent* he = gethostbyname(host);
	if (!he) {
		fprintf(stderr, "gethostbyname error\n");
		return;
	}
	const struct in_addr* addr = (struct in_addr*)he->h_addr;

	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		printf("create socket error: %s(%d)\n", strerror(errno), errno);
		return;
	}

	struct timeval timeout = {5, 0};
    setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	printf("action to %s %d\n", inet_ntoa(*addr), port);
	
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ((struct in_addr *)(he->h_addr))->s_addr;
	sa.sin_port = htons(port);

	int err = connect(sd, (struct sockaddr*)&sa, sizeof(sa));
	if (err < 0) {
		printf("connect error.: %s(%d)\n", strerror(errno), errno);
		close(sd);
		return;
	}
	
	printf("connected\n");
	
	close(sd);
}
