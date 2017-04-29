// tcp_syn.cpp

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
#include <netinet/tcp.h>

#include "tcp_syn.h"

void tcp_syn::action(const char* host, int port) {
	struct hostent* he = gethostbyname(host);
	if (!he) {
		fprintf(stderr, "gethostbyname error\n");
		return;
	}
	const char* name = he->h_name;
	const struct in_addr* addr = (struct in_addr*)he->h_addr;

	int sd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sd < 0) {
		fprintf(stderr, "create socket error: %s(%d)\n", strerror(errno), errno);
		return;
	}
	setuid(getuid());

	struct timeval timeout = {5, 0}; // 5s
    setsockopt(sd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

	printf("tcp_syn %s (%s) %d\n", name, inet_ntoa(*addr), port);

	int sport = 12345, dport = port;
	char buf[128];
//	if (send_syn(sd, addr, buf, sizeof(buf), sport, dport) < 0) {
//		close(sd);
//		return;
//	}
  for (int i = 0; i < 8; ++i) {
    if (recv_acksyn(sd, addr, buf, sizeof(buf), sport, dport) < 0) {
      close(sd);
      return;
    }
  }
//	if (send_rst(sd, addr, buf, sizeof(buf), sport, dport) < 0) {
//		close(sd);
//		return;
//	}
	
	close(sd);
}

int tcp_syn::send_syn(int sd, const struct in_addr* addr, char* buf, int len, int sport, int dport) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->s_addr;
	sa.sin_port = htons(dport);
	
	len = sizeof(struct tcphdr);
	
	struct tcphdr* tcp = (struct tcphdr*)buf;
	memset(tcp, 0, len);
	tcp->source = htons(sport); 
	tcp->dest = htons(dport);
	tcp->seq = htonl(1000000);
	tcp->doff = len / 4;
	tcp->syn = 1;
	tcp->window = htons(65535);
	tcp->check = check_sum(buf, len);
	
	printf("send_syn %s source=%d dest=%d seq=%u ack_seq=%u doff=%d fin=%d syn=%d rst=%d psh=%d ack=%d urg=%d window=%d check=%d\n",
		inet_ntoa(*addr), ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),
		tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->window, tcp->check);

	int ret = sendto(sd, buf, len, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return 0;
}

int tcp_syn::recv_acksyn(int sd, const struct in_addr* addr, char* buf, int len, int sport, int dport) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->s_addr;
	sa.sin_port = htons(dport);
	
	socklen_t salen = sizeof(sa);
  printf("recv_acksyn dst=%s port=%d len=%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), salen);

	int ret = recvfrom(sd, buf, len, 0, (struct sockaddr*)&sa, &salen);
	if (ret < 0) {
		fprintf(stderr, "recvfrom error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	struct ip* ip = (struct ip*)buf;
	struct tcphdr* tcp = (struct tcphdr*)(buf + sizeof(struct ip));
	
  printf("recv_acksyn dst=%s port=%d len=%d\n", inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), salen);
  printf("recv_acksyn len=%d ip_src=%s ip_dst=%s\n", ret, inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst));
	printf("recv_acksyn source=%d dest=%d seq=%u ack_seq=%u doff=%d fin=%d syn=%d rst=%d psh=%d ack=%d urg=%d window=%d check=%d\n",
		ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),
		tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->window, tcp->check);

	return 0;
}

int tcp_syn::send_rst(int sd, const struct in_addr* addr, char* buf, int len, int sport, int dport) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = addr->s_addr;
	sa.sin_port = htons(dport);
	
	len = sizeof(struct tcphdr);
	
	struct tcphdr* tcp = (struct tcphdr*)buf;
	memset(tcp, 0, len);
	tcp->source = htons(sport); 
	tcp->dest = htons(dport);
	tcp->seq = 0;
	tcp->doff = len / 4;
	tcp->rst = 1;
	tcp->window = htons(65535);
	tcp->check = check_sum(buf, len);
		
	printf("send_rst %s source=%d dest=%d seq=%u ack_seq=%u doff=%d fin=%d syn=%d rst=%d psh=%d ack=%d urg=%d window=%d check=%d\n",
		inet_ntoa(*addr), ntohs(tcp->source), ntohs(tcp->dest), ntohl(tcp->seq), ntohl(tcp->ack_seq),
		tcp->doff, tcp->fin, tcp->syn, tcp->rst, tcp->psh, tcp->ack, tcp->urg, tcp->window, tcp->check);

	int ret = sendto(sd, buf, len, 0, (struct sockaddr*)&sa, sizeof(sa));
	if (ret < 0) {
		fprintf(stderr, "sendto error: %s(%d)\n", strerror(errno), errno);
		return ret;
	}
	
	return 0;
}

uint16_t tcp_syn::check_sum(const char* buf, int len) { 
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
