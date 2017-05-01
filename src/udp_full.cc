// udp_full.cpp

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
#include <netinet/udp.h>

#include "udp_full.h"

void udp_full::action(const char* shost, int sport, const char* dhost, int dport) {
	srandom(time(NULL));
	
	if (sport == 0) {
		sport = random() % 30000 + 30000;
	}

	struct hostent* sh = gethostbyname(shost);
	if (!sh) {
		fprintf(stderr, "gethostbyname source host error\n");
		return;
	}
	struct in_addr saddr;
	memcpy(&saddr, sh->h_addr, sizeof(in_addr));
	
	struct hostent* dh = gethostbyname(dhost);
	if (!dh) {
		fprintf(stderr, "gethostbyname dest host error\n");
		return;
	}
	struct in_addr daddr;
	memcpy(&daddr, dh->h_addr, sizeof(in_addr));

	int ssd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
	if (ssd < 0) {
		fprintf(stderr, "create socket error: %s(%d)\n", strerror(errno), errno);
		return;
	}
	
	int rsd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (rsd < 0) {
		fprintf(stderr, "create socket error: %s(%d)\n", strerror(errno), errno);
		return;
	}
	
	setuid(getuid());

	struct timeval timeout = {5, 0}; // 5s
	setsockopt(ssd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
	setsockopt(rsd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	char sip[32];
	char dip[32];
	strcpy(sip, inet_ntoa(saddr));
	strcpy(dip, inet_ntoa(daddr));
	printf("action from %s %d to %s %d\n", sip, sport, dip, dport);

	char buf[128];
	if (send_packet(ssd, saddr, daddr, buf, sizeof(buf), sport, dport) < 0) {
		goto exit;
	}
	
	while (true) {
		int ret = recv_packet(rsd, saddr, daddr, buf, sizeof(buf), sport, dport);
		if (ret < 0) {
			goto exit;
		} else if (ret > 0) {
			break;
		}
	}

exit:
	close(ssd);
	close(rsd);
}

int udp_full::send_packet(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport) {
	memset(buf, 0, len);
	
	((u_int32_t*)buf)[0] = saddr.s_addr;
	((u_int32_t*)(buf + 4))[0] = daddr.s_addr;
	buf[8] = 0;
	buf[9] = IPPROTO_UDP;
	((u_int16_t*)(buf + 10))[0] = htons(sizeof(struct udphdr) + 4);

	struct udphdr* udp = (struct udphdr*)(buf + 12);
	udp->source = htons(sport); 
	udp->dest = htons(dport);
	udp->len = htons(sizeof(struct udphdr) + 4);
	udp->check = check_sum(buf, 12 + sizeof(struct udphdr) + 4);
	
	printf("send packet udphdr: source=%d dest=%d len=%d check=%04x\n",
		ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len), udp->check);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = daddr.s_addr;
	
	int ret = sendto(sd, buf + 12, sizeof(struct udphdr) + 4, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return ret;
}

int udp_full::recv_packet(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	socklen_t salen = sizeof(sa);

	int ret = recvfrom(sd, buf, len, 0, (struct sockaddr*)&sa, &salen);
	if (ret < 0) {
		fprintf(stderr, "recvfrom error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	struct iphdr* ip = (struct iphdr*)buf;
	struct icmphdr* icmp = (struct icmphdr*)(buf + sizeof(struct iphdr));
	
	char sip[32];
	char dip[32];
	sprintf(sip, "%s", inet_ntoa(*(struct in_addr*)&(ip->saddr)));
	sprintf(dip, "%s", inet_ntoa(*(struct in_addr*)&(ip->daddr)));

	if (ip->saddr != daddr.s_addr || icmp->type != ICMP_DEST_UNREACH || icmp->code != ICMP_PORT_UNREACH) {
//		printf("recv_packet filtered - ip: packet_len=%d saddr=%s daddr=%s\n", ret, sip, dip);
		return 0;
	}

	printf("recv packet addr: dst=%s port=%d len=%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), salen);
	printf("recv packet iphdr: packet_len=%d saddr=%s daddr=%s\n", ret, sip, dip);
	printf("recv packet icmphdr: type=%d code=%d\n", icmp->type, icmp->code);

	return ret;
}

u_int16_t udp_full::check_sum(const char* buf, int len) { 
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
