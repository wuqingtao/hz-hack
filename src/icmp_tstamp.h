// icmp_tstamp.h

#ifndef __ICMP_TSTAMP_H__
#define __ICMP_TSTAMP_H__

#include <sys/types.h>

class icmp_tstamp {
public:
	void action(const char* host);
	
private:
	int send_packet(int sd, struct in_addr addr, char* buf, int len, u_int16_t seq);
	int recv_packet(int sd, struct in_addr addr, char* buf, int len, u_int16_t seq);
	u_int16_t check_sum(const char* buf, int len);
};

#endif // __ICMP_TSTAMP_H__
