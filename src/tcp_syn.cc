// tcp_syn.cpp

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
#include <netinet/tcp.h>

#include "tcp_syn.h"

void tcp_syn::action(const char* shost, int sport, const char* dhost, int dport) {
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

	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sd < 0) {
		fprintf(stderr, "create socket error: %s(%d)\n", strerror(errno), errno);
		return;
	}
	
	setuid(getuid());

	struct timeval timeout = {5, 0}; // 5s
	setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
	setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	char sip[32];
	char dip[32];
	strcpy(sip, inet_ntoa(saddr));
	strcpy(dip, inet_ntoa(daddr));
	printf("action from %s %d to %s %d\n", sip, sport, dip, dport);
	
	u_int32_t seq = random();

	char buf[128];
	if (send_syn(sd, saddr, daddr, buf, sizeof(buf), sport, dport, seq) < 0) {
		goto exit;
	}
	while (true) {
		int ret = recv_acksyn(sd, saddr, daddr, buf, sizeof(buf), sport, dport, seq);
		if (ret < 0) {
			goto exit;
		} else if (ret > 0) {
			break;
		}
	}
	if (send_rst(sd, saddr, daddr, buf, sizeof(buf), sport, dport, seq) < 0) {
		goto exit;
	}

exit:
	close(sd);
}

int tcp_syn::send_syn(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport, u_int32_t seq) {
	memset(buf, 0, len);
	
	((u_int32_t*)buf)[0] = saddr.s_addr;
	((u_int32_t*)(buf + 4))[0] = daddr.s_addr;
	buf[8] = 0;
	buf[9] = IPPROTO_TCP;
	((u_int16_t*)(buf + 10))[0] = htons(sizeof(struct tcphdr));

	struct tcphdr* tcp = (struct tcphdr*)(buf + 12);
	tcp->source = htons(sport); 
	tcp->dest = htons(dport);
	tcp->seq = htonl(seq);
	tcp->doff = sizeof(struct tcphdr) / 4;
	tcp->syn = 1;
	tcp->window = htons(4096);
	tcp->check = check_sum(buf, 12 + sizeof(struct tcphdr));
	
	printf("send syn tcphdr: source=%d dest=%d seq=%u ack_seq=%u doff=%d fin=%d syn=%d rst=%d psh=%d ack=%d urg=%d window=%d check=%04x\n",
		ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),
		tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, ntohs(tcp->window), tcp->check);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = daddr.s_addr;
	
	int ret = sendto(sd, buf + 12, sizeof(struct tcphdr), 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return ret;
}

int tcp_syn::recv_acksyn(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport, u_int32_t& seq) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	socklen_t salen = sizeof(sa);

	int ret = recvfrom(sd, buf, len, 0, (struct sockaddr*)&sa, &salen);
	if (ret < 0) {
		fprintf(stderr, "recvfrom error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	struct iphdr* ip = (struct iphdr*)buf;
	struct tcphdr* tcp = (struct tcphdr*)(buf + sizeof(struct iphdr));
	
	char sip[32];
	char dip[32];
	sprintf(sip, "%s", inet_ntoa(*(struct in_addr*)&(ip->saddr)));
	sprintf(dip, "%s", inet_ntoa(*(struct in_addr*)&(ip->daddr)));

	if (ip->saddr != daddr.s_addr || dport != ntohs(tcp->source) ||
		tcp->syn != 1 || tcp->ack != 1 || ntohl(tcp->ack_seq) != seq + 1) {
//		printf("recv_acksyn filtered - ip: packet_len=%d saddr=%s daddr=%s\n", ret, sip, dip);
		return 0;
	}
	
	seq = ntohl(tcp->seq) + 1;

	printf("recv acksyn addr: dst=%s port=%d len=%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), salen);
	printf("recv acksyn iphdr: packet_len=%d saddr=%s daddr=%s\n", ret, sip, dip);
	printf("recv acksyn tcphdr: source=%d dest=%d seq=%u ack_seq=%u doff=%d fin=%d syn=%d rst=%d psh=%d ack=%d urg=%d window=%d check=%04x\n",
		ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),
		tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, ntohs(tcp->window), tcp->check);

	return ret;
}

int tcp_syn::send_rst(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport, u_int32_t seq) {
	memset(buf, 0, len);
	
	((u_int32_t*)buf)[0] = saddr.s_addr;
	((u_int32_t*)(buf + 4))[0] = daddr.s_addr;
	buf[8] = 0;
	buf[9] = IPPROTO_TCP;
	((u_int16_t*)(buf + 10))[0] = htons(sizeof(struct tcphdr));

	struct tcphdr* tcp = (struct tcphdr*)(buf + 12);
	tcp->source = htons(sport); 
	tcp->dest = htons(dport);
	tcp->seq = htonl(seq);
	tcp->doff = sizeof(struct tcphdr) / 4;
	tcp->rst = 1;
	tcp->window = htons(4096);
	tcp->check = check_sum(buf, 12 + sizeof(struct tcphdr));
		
	printf("send rst tcphdr: source=%d dest=%d seq=%u ack_seq=%u doff=%d fin=%d syn=%d rst=%d psh=%d ack=%d urg=%d window=%d check=%x\n",
		ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),
		tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, ntohs(tcp->window), tcp->check);

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = daddr.s_addr;

	int ret = sendto(sd, buf + 12, sizeof(struct tcphdr), 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return ret;
}

u_int16_t tcp_syn::check_sum(const char* buf, int len) { 
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
