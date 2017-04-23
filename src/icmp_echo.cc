// icmp_echo.cpp

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

#include "icmp_echo.h"

void icmp_echo::action(const char* host) {
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

	printf("Ping %s (%s) %d bytes of data\n", name, inet_ntoa(*addr), 56);
	
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->s_addr;

	char sbuf[64];
	char rbuf[128];
	const int scount = 8;
	int rcount = 0;
	double min_rtt = 10e6, max_rtt = -1, avg_rtt = 0;
	
	init_send(sbuf);
	for (uint16_t seq = 1; seq <= scount; ++seq) {
		if (do_send(sd, *addr, sbuf, sizeof(sbuf), seq) >= 0) {
			double rtt;
			if (do_recv(sd, *addr, rbuf, sizeof(rbuf), seq, rtt) >= 0) {
				++rcount;
				avg_rtt += rtt;
				if (rtt < min_rtt) {
					min_rtt = rtt;
				}
				if (rtt > max_rtt) {
					max_rtt = rtt;
				}
			}
		}
		sleep(1);
	}
	
	printf("%d packets sent, %d packets received, %d(%.1f%%) packets lost\n",
		scount, rcount, scount - rcount, (scount - rcount) * 100.0 / scount);
	if (rcount > 0) {
		printf("min_rtt=%.3fms max_rtt=%.3fms avg_rtt=%.3fms\n",
			min_rtt, max_rtt, (rcount > 0 ? avg_rtt / rcount : 0));
	}
		
	close(sd);
}

void icmp_echo::init_send(char* buf) {
	struct icmp* icmp = (struct icmp*)buf;
	icmp->icmp_type = ICMP_ECHO;
	icmp->icmp_code = 0;
	icmp->icmp_cksum = 0;
	icmp->icmp_id = getpid();
}

int icmp_echo::do_send(int sd, struct in_addr addr, char* buf, int len, uint16_t seq) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr.s_addr;
	
	struct icmp* icmp = (struct icmp*)buf;
	icmp->icmp_seq = seq;
	gettimeofday((struct timeval*)icmp->icmp_data, NULL);
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = check_sum(buf, len);
	
	int ret = sendto(sd, buf, len, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return 0;
}

int icmp_echo::do_recv(int sd, struct in_addr addr, char* buf, int len, uint16_t seq, double& rtt) {
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
	
	if (ret < 16) {
		fprintf(stderr, "recvfrom icmp length error: %d\n", ret);
		return -1;
	}
	
	const struct icmp* icmp = (struct icmp*)buf;
	if (icmp->icmp_type != ICMP_ECHOREPLY) {
		fprintf(stderr, "recvfrom icmp type error: %d\n", icmp->icmp_type);
		return -1;
		
	}
	
	if (icmp->icmp_seq != seq) {
		fprintf(stderr, "recvfrom icmp seq error: %d\n", icmp->icmp_seq);
		return -1;
	}
	
	if (icmp->icmp_id != getpid()) {
		fprintf(stderr, "recvfrom icmp id error: 0x%08x\n", icmp->icmp_id);
		return -1;
	}
	
	struct timeval* stime = (struct timeval*)icmp->icmp_data;
	struct timeval rtime;
	gettimeofday(&rtime, NULL);
	rtt = (rtime.tv_sec * 1000 + rtime.tv_usec / 1000.0 - stime->tv_sec * 1000 - stime->tv_usec / 1000.0);
	
	printf("%d bytes from %s icmp_seq=%d ttl=%d rtt=%.1fms\n",
		ret, inet_ntoa(ip->ip_src), seq, ttl, rtt);

	return 0;
}

uint16_t icmp_echo::check_sum(const char* buf, int len) { 
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
