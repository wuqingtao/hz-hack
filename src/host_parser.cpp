// host_parser.cpp

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

#include "host_parser.h"

void HostParser::action(const char* host) {
	printf("host: %s\n", host);
	
	struct hostent* he = gethostbyname(host);
	if (!he) {
		printf("gethostbyname failed\n");
		return;
	}
	
	printf("name: %s\n", he->h_name);

	for (char** alias = he->h_aliases; *alias != NULL; ++alias) {
		printf("alias: %s\n", *alias);
	}
	
	char ip[32];
	for (char** addr = he->h_addr_list; *addr != NULL; ++addr) {	
		inet_ntop(he->h_addrtype, *addr, ip, sizeof(ip));
		printf("ip: %s\n", ip);
	}
}
