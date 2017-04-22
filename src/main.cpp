// main.cpp

#include <stdio.h> 
#include <stdlib.h>
#include <string.h>

#include "host_parser.h"
#include "icmp_echo.h"
#include "tcp_full.h"

void usage();

int main(int argc, char** argv) {
	if (argc < 2) {
		usage();
		return 0;
	}
	
	if (strcmp(argv[1], "host_parser") == 0) {
		if (argc != 3) {
			usage();
			return 0;
		}
		const char* host = argv[2];
		HostParser hostParser;
		hostParser.action(host);
	} else if (strcmp(argv[1], "icmp_echo") == 0) {
		if (argc != 3) {
			usage();
			return 0;
		}
		const char* host = argv[2];
		IcmpEcho icmpEcho;
		icmpEcho.action(host);
	} else if (strcmp(argv[1], "tcp_full") == 0) {
		if (argc != 4) {
			usage();
			return 0;
		}
		const char* host = argv[2];
		int port = atoi(argv[3]);
		TcpFull tcpFull;
		tcpFull.action(host, port);
	} else {
		usage();
	}
	
	return 0;
}

void usage() {
	printf("usage:\n");
	printf("host_parser <host>\n");
	printf("icmp_echo <host/ip> <port>\n");
	printf("tcp_full <host/ip> <port>\n");
}
