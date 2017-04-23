// host_parser.cpp

#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>

#include "host_parser.h"

void HostParser::action(const char* host) {
	struct hostent* he = gethostbyname(host);
	if (!he) {
		fprintf(stderr, "gethostbyname error");
		return;
	}
	
	printf("name: %s\n", he->h_name);

	for (char** alias = he->h_aliases; *alias != NULL; ++alias) {
		printf("alias: %s\n", *alias);
	}
	
	for (char** addr = he->h_addr_list; *addr != NULL; ++addr) {
		char* ip = inet_ntoa(*(struct in_addr*)(*addr));
		printf("addr: %s\n", ip);
	}
}
