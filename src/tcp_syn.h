// tcp_syn.h

#ifndef __TCP_SYN_H__
#define __TCP_SYN_H__

#include <stdint.h>

class tcp_syn {
public:
	void action(const char* host, int port);
	
private:
	int send_syn(int sd, const struct in_addr* addr, char* buf, int len, int sport, int dport);
	int recv_acksyn(int sd, const struct in_addr* addr, char* buf, int len, int sport, int dport);
	int send_rst(int sd, const struct in_addr* addr, char* buf, int len, int sport, int dport);
	uint16_t check_sum(const char* buf, int len);
};

#endif // __TCP_SYN_H__
