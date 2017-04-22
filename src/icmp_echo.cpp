// icmp_echo.cpp

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "icmp_echo.h"

void IcmpEcho::action(const char* host) {
	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sd < 0) {
		perror("create socket error");
		return;
	}
	setuid(getuid());

	struct hostent* he = gethostbyname(host);
	if (!he) {
		perror("gethostbyname error");
		return;
	}

	printf("PING %s (%s) %d bytes of data\n", he->h_name, inet_ntoa(*(struct in_addr*)he->h_addr), 56);
	
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = ((struct in_addr *)(he->h_addr))->s_addr;

	char sbuf[64];
	char rbuf[1024];
	
	struct icmp* sicmp = (struct icmp*)sbuf;
	sicmp->icmp_type = ICMP_ECHO;
	sicmp->icmp_code = 0;
	sicmp->icmp_cksum = 0;
	sicmp->icmp_id = getpid();
	
	for (int i = 0; i < 8; ++i) {
		sicmp->icmp_seq = (uint16_t)i + 1;
		struct timeval* stime = (struct timeval*)sicmp->icmp_data;
		gettimeofday(stime, NULL);
		sicmp->icmp_cksum = chksum(sbuf, sizeof(sbuf));

		int slen = sendto(sd, sbuf, sizeof(sbuf), 0, (struct sockaddr*)&sa, sizeof(sa));
		if (slen < 0) {
			perror("sendto error");
			continue;
		}
		
		socklen_t salen = sizeof(sa);
		int rlen = recvfrom(sd, rbuf, sizeof(rbuf), 0, (struct sockaddr*)&sa, &salen);
		if (rlen < 0) {
			perror("recvfrom error");
			continue;
		}
		
		const struct ip* rip = (struct ip *)rbuf;
		int riplen = rip->ip_hl << 2;
		rlen -= riplen;
		const struct icmp* ricmp = (struct icmp*)(rbuf + riplen);
		
		uint8_t ttl = rip->ip_ttl;

		struct timeval rtime;
		gettimeofday(&rtime, NULL);
		double rtt = (rtime.tv_sec * 1000 + rtime.tv_usec / 1000.0 - stime->tv_sec * 1000 - stime->tv_usec / 1000.0);

		printf("%d bytes from %s icmp_seq=%d ttl=%d time=%.1fms\n",
			rlen, inet_ntoa(rip->ip_src), ricmp->icmp_seq, ttl, rtt);
		
		sleep(1);
	}
}

uint16_t IcmpEcho::chksum(const char* buf, int len) { 
   uint32_t sum = 0;
   while (len > 1)
   {
     sum += *(uint16_t*)buf;
	 buf += 2;
     len -= 2;
   }
   if (len == 1) {
       sum += *(uint8_t*)buf;
   }
   sum = (sum >> 16) + (sum & 0xffff);
   sum += (sum >> 16);

   uint16_t answer = ~sum;
   return answer;
}
