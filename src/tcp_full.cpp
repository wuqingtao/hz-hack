// tcp_full.cpp

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "tcp_full.h"

void TcpFull::action(const char* host, int port) {
	printf("%s:%d\n", host, port);
	
	// parse ip from host
	struct hostent* he = gethostbyname(host);
	if (!he) {
		printf("failed to gethostbyname: %s(errno: %d)\n", strerror(errno), errno);
		return;
	}
	
	char ip[32];
	inet_ntop(he->h_addrtype, he->h_addr, ip, sizeof(ip));
	printf("%s\n", ip);
	
	// make socket address
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ((struct in_addr *)(he->h_addr))->s_addr;
	sa.sin_port = htons(port);
	
	// make socket
	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		printf("create socket fialed: %s(errno: %d)\n", strerror(errno), errno);
		return;
	}
	printf("socket created\n");

	// connect
	int err = connect(sd, (struct sockaddr*)&sa, sizeof(sa));
	if (err == -1) {
		printf("connect fialed.: %s(%d)\n", strerror(errno), errno);
		return;
	}
	printf("connected\n");
	
	// receive
	char buf[4096];
	int len = recv(sd, buf, sizeof(buf), 0);
	if (len <= 0) {
		printf("recv fialed.: %s(errno: %d)\n", strerror(errno), errno);
		return;
	}
	
	// print result
	buf[len] = 0;
	printf("recieved: %d %s\n", len, buf);
	
	// close
	close(sd);
}
