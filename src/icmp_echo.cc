// icmp_echo.cpp

#include <stdio.h>
#include <stdlib.h>
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
	for (u_int16_t seq = 1; seq <= scount; ++seq) {
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
	struct icmphdr* icmp = (struct icmphdr*)buf;
	icmp->type = ICMP_ECHO;
	icmp->code = 0;
	icmp->checksum = 0;
	icmp->un.echo.id = getpid();
}

int icmp_echo::do_send(int sd, struct in_addr addr, char* buf, int len, u_int16_t seq) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr.s_addr;
	
	struct icmphdr* icmp = (struct icmphdr*)buf;
	icmp->un.echo.sequence = seq;
	gettimeofday((struct timeval*)(buf + sizeof(struct icmphdr)), NULL);
	icmp->checksum = 0;
	icmp->checksum = check_sum(buf, len);
	
	int ret = sendto(sd, buf, len, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return 0;
}

int icmp_echo::do_recv(int sd, struct in_addr addr, char* buf, int len, u_int16_t seq, double& rtt) {
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
	
	const struct iphdr* ip = (struct iphdr *)buf;
	u_int8_t ttl = ip->ttl;

	int iplen = ip->ihl << 2;
	ret -= iplen;
	buf += iplen;
	
	if (ret < 16) {
		fprintf(stderr, "recvfrom icmp length error: %d\n", ret);
		return -1;
	}
	
	const struct icmphdr* icmp = (struct icmphdr*)buf;
	if (icmp->type != ICMP_ECHOREPLY) {
		fprintf(stderr, "recvfrom icmp_type error: %d\n", icmp->type);
		return -1;
		
	}
	
	if (icmp->un.echo.id != getpid()) {
		fprintf(stderr, "recvfrom icmp_id error: 0x%08x\n", icmp->un.echo.id);
		return -1;
	}
	
	if (icmp->un.echo.sequence != seq) {
		fprintf(stderr, "recvfrom icmp_seq error: %d\n", icmp->un.echo.sequence);
		return -1;
	}
	
	struct timeval* stime = (struct timeval*)(buf + sizeof(struct icmphdr));
	struct timeval rtime;
	gettimeofday(&rtime, NULL);
	rtt = (rtime.tv_sec * 1000 + rtime.tv_usec / 1000.0 - stime->tv_sec * 1000 - stime->tv_usec / 1000.0);
	
	printf("%d bytes from %s icmp_seq=%d ttl=%d rtt=%.1fms\n",
		ret, inet_ntoa(*(struct in_addr*)&(ip->saddr)), seq, ttl, rtt);

	return 0;
}

u_int16_t icmp_echo::check_sum(const char* buf, int len) { 
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
