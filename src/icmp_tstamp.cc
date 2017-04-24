// icmp_tstamp.cpp

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "icmp_tstamp.h"

void icmp_tstamp::action(const char* host) {
	struct hostent* he = gethostbyname(host);
	if (!he) {
		fprintf(stderr, "gethostbyname error\n");
		return;
	}
	const char* name = he->h_name;
	const struct in_addr* addr = (struct in_addr*)he->h_addr;

	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sd < 0) {
		fprintf(stderr, "create socket error: %s(%d)\n", strerror(errno), errno);
		return;
	}
	setuid(getuid());

	struct timeval timeout = {5, 0}; // 5s
    setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	printf("icmp_tstamp %s (%s)\n", name, inet_ntoa(*addr));
	
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->s_addr;

	char sbuf[20];
	char rbuf[128];
	
	init_send(sbuf);
	uint16_t seq = 79;
	if (do_send(sd, *addr, sbuf, sizeof(sbuf), seq) >= 0) {
		do_recv(sd, *addr, rbuf, sizeof(rbuf), seq);
	}
	
	close(sd);
}

void icmp_tstamp::init_send(char* buf) {
	struct icmp* icmp = (struct icmp*)buf;
	icmp->icmp_type = ICMP_TSTAMP;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_id = getpid();
}

int icmp_tstamp::do_send(int sd, struct in_addr addr, char* buf, int len, uint16_t seq) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr.s_addr;
	
	struct icmp* icmp = (struct icmp*)buf;
	icmp->icmp_seq = seq;
	struct timeval time;
	gettimeofday(&time, NULL);
	icmp->icmp_otime = time.tv_sec;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = check_sum(buf, len);
	
	int ret = sendto(sd, buf, len, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return 0;
}

int icmp_tstamp::do_recv(int sd, struct in_addr addr, char* buf, int len, uint16_t seq) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr.s_addr;

	socklen_t salen = sizeof(sa);
	int ret = recvfrom(sd, buf, len, 0, (struct sockaddr*)&sa, &salen);
	if (ret < 0) {
		fprintf(stderr, "recvfrom error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	const struct ip* ip = (struct ip *)buf;
	uint8_t ttl = ip->ip_ttl;

	int iplen = ip->ip_hl << 2;
	ret -= iplen;
	buf += iplen;
	
	if (ret < 20) {
		fprintf(stderr, "recvfrom icmp length error: %d\n", ret);
		return -1;
	}
	
	const struct icmp* icmp = (struct icmp*)buf;
	if (icmp->icmp_type != ICMP_TSTAMPREPLY) {
		fprintf(stderr, "recvfrom icmp_type error: %d\n", icmp->icmp_type);
		return -1;
		
	}
	
	if (icmp->icmp_id != getpid()) {
		fprintf(stderr, "recvfrom icmp_id error: 0x%08x\n", icmp->icmp_id);
		return -1;
	}
	
	if (icmp->icmp_seq != seq) {
		fprintf(stderr, "recvfrom icmp_seq error: %d\n", icmp->icmp_seq);
		return -1;
	}
	
	printf("from %s otime=%u rtime=%u ttime=%u\n",
		inet_ntoa(ip->ip_src), icmp->icmp_otime, icmp->icmp_rtime, icmp->icmp_ttime);

	return 0;
}

uint16_t icmp_tstamp::check_sum(const char* buf, int len) { 
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
   while (sum >> 16) {
	   sum = (sum & 0xffff) + (sum >> 16);
   }
   return (uint16_t)~(sum);
}
