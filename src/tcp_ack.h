// tcp_ack.h

#ifndef __TCP_ACK_H__
#define __TCP_ACK_H__

#include <sys/types.h>

class tcp_ack {
public:
	void action(const char* shost, int sport, const char* dhost, int dport);
	
private:
	int send_ack(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport, u_int32_t seq);
	int recv_rst(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport);
	u_int16_t check_sum(const char* buf, int len);
};

#endif // __TCP_ACK_H__
