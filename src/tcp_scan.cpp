// tcp_scan.cpp

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "tcp_scan.h"

void TcpScan::scan(const char* host, int port) {
	// parse ip from host
	struct hostent* he = gethostbyname(host);
	if (!he) {
		printf("failed to gethostbyname: %s(errno: %d)\n", strerror(errno), errno);
		return;
	}
	
	// make socket address
	struct socket_addr_in sa;
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

	// connect
	int err = connect(sd, (struct sockaddr*)&sa, sizeof(sa));
	if (err == -1) {
		printf("connect fialed.: %s(errno: %d)\n", strerror(errno), errno);
		return;
	}
	
	// receive
	char buf[4096];
	int len = recv(sd, buf, sizeof(buf), 0);
	if (len == -1) {
		printf("recv fialed.: %s(errno: %d)\n", strerror(errno), errno);
		return;
	}
	
	// print result
	buf[len] = 0;
	printf("recieved: %s\n", buf);
	
	// close
	close(sd);
}
