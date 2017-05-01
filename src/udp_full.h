// udp_full.h

#ifndef __UDP_FULL_H__
#define __UDP_FULL_H__

#include <sys/types.h>

class udp_full {
public:
	void action(const char* shost, int sport, const char* dhost, int dport);
	
private:
	int send_packet(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport);
	int recv_packet(int sd, const struct in_addr saddr, const struct in_addr daddr, char* buf, int len, u_int16_t sport, u_int16_t dport);
	u_int16_t check_sum(const char* buf, int len);
};

#endif // __UDP_FULL_H__
