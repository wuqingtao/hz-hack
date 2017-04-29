// main.cpp

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "host_parse.h"
#include "icmp_echo.h"
#include "icmp_tstamp.h"
#include "tcp_syn.h"
#include "tcp_full.h"

void usage();

int main(int argc, char** argv) {
	if (argc < 2) {
		usage();
		return 0;
	}
	
	if (strcmp(argv[1], "host_parse") == 0) {
		if (argc != 3) {
			usage();
			return 0;
		}
		const char* host = argv[2];
		host_parse hp;
		hp.action(host);
	} else if (strcmp(argv[1], "icmp_echo") == 0) {
		if (argc != 3) {
			usage();
			return 0;
		}
		const char* host = argv[2];
		icmp_echo ie;
		ie.action(host);
	} else if (strcmp(argv[1], "icmp_tstamp") == 0) {
		if (argc != 3) {
			usage();
			return 0;
		}
		const char* host = argv[2];
		icmp_tstamp it;
		it.action(host);
	} else if (strcmp(argv[1], "tcp_syn") == 0) {
		if (argc != 4) {
			usage();
			return 0;
		}
		const char* host = argv[2];
		int port = atoi(argv[3]);
		tcp_syn ts;
		ts.action(host, port);
	} else if (strcmp(argv[1], "tcp_full") == 0) {
		if (argc != 4) {
			usage();
			return 0;
		}
		const char* host = argv[2];
		int port = atoi(argv[3]);
		tcp_full tf;
		tf.action(host, port);
	} else {
		usage();
	}
	
	return 0;
}

void usage() {
	printf("usage:\n");
	printf("  ./hztrack host_parse <host>\n");
	printf("  ./hztrack icmp_echo <host/ip>\n");
	printf("  ./hztrack icmp_tstamp <host/ip>\n");
	printf("  ./hztrack tcp_syn <host/ip> <port>\n");
	printf("  ./hztrack tcp_full <host/ip> <port>\n");
}
