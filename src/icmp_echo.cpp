// icmp_echo.cpp

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

#include "icmp_echo.h"

void IcmpEcho::action(const char* host) {
	printf("not implemented");
	
}
