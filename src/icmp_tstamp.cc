// icmp_tstamp.cpp

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
	srand(time(NULL));
	
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

	printf("action to %s (%s)\n", name, inet_ntoa(*addr));

	u_int16_t seq = rand();

	char buf[128];
	if (send_packet(sd, *addr, buf, sizeof(buf), seq) >= 0) {
		recv_packet(sd, *addr, buf, sizeof(buf), seq);
	}
	
	close(sd);
}

int icmp_tstamp::send_packet(int sd, struct in_addr addr, char* buf, int len, u_int16_t seq) {
	memset(buf, 0, len);
	
	struct icmphdr* icmp = (struct icmphdr*)buf;
	icmp->type = ICMP_TSTAMP;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = getpid();
	icmp->un.echo.sequence = seq;

	struct timeval time;
	gettimeofday(&time, NULL);
	((u_int32_t*)(buf + sizeof(struct icmphdr)))[0] = htonl((u_int32_t)(time.tv_sec % 86400 * 1000 + time.tv_usec / 1000));
	
	icmp->checksum = check_sum(buf, len);
	
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr.s_addr;
	
	int ret = sendto(sd, buf, sizeof(struct icmphdr) + 12, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return 0;
}

int icmp_tstamp::recv_packet(int sd, struct in_addr addr, char* buf, int len, u_int16_t seq) {
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
	
	if (ret < (int)sizeof(struct iphdr) + 20) {
		fprintf(stderr, "recvfrom length error: %d\n", ret);
		return -1;
	}

	const struct iphdr* ip = (struct iphdr *)buf;
	const struct icmphdr* icmp = (struct icmphdr*)(buf + sizeof(iphdr));
		
	char sip[32];
	char dip[32];
	sprintf(sip, "%s", inet_ntoa(*(struct in_addr*)&(ip->saddr)));
	sprintf(dip, "%s", inet_ntoa(*(struct in_addr*)&(ip->daddr)));
	
	if (ip->saddr != addr.s_addr) {
		return -1;
	}
	
	if (icmp->type != ICMP_TSTAMPREPLY) {
		fprintf(stderr, "recvfrom icmp type error: %d\n", icmp->type);
		return -1;
	}
	
	if (icmp->un.echo.id != getpid()) {
		fprintf(stderr, "recvfrom icmp id error: 0x%08x\n", icmp->un.echo.id);
		return -1;
	}
	
	if (icmp->un.echo.sequence != seq) {
		fprintf(stderr, "recvfrom icmp sequence error: %d\n", icmp->un.echo.sequence);
		return -1;
	}

	u_int32_t otime = ntohl(((u_int32_t*)(buf + sizeof(struct iphdr) + sizeof(struct icmphdr)))[0]);
	u_int32_t rtime = ntohl(((u_int32_t*)(buf + sizeof(struct iphdr) + sizeof(struct icmphdr)))[1]);
	u_int32_t ttime = ntohl(((u_int32_t*)(buf + sizeof(struct iphdr) + sizeof(struct icmphdr)))[2]);

	printf("recv packet addr: dst=%s port=%d len=%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), salen);
	printf("recv packet iphdr: packet_len=%d saddr=%s daddr=%s\n", ret, sip, dip);
	printf("recv packet icmphdr: otime=%u rtime=%u ttime=%u\n", otime, rtime, ttime);

	return 0;
}

u_int16_t icmp_tstamp::check_sum(const char* buf, int len) { 
   u_int32_t sum = 0;
   while (len > 1) {
     sum += *(u_int16_t*)buf;
	 buf += 2;
     len -= 2;
   }
   if (len == 1) {
       sum += *(u_int8_t*)buf;
   }
   while (sum >> 16) {
	   sum = (sum & 0xffff) + (sum >> 16);
   }
   return (u_int16_t)~(sum);
}
