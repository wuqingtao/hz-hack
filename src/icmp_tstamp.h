// icmp_tstamp.h

#ifndef __ICMP_TSTAMP_H__
#define __ICMP_TSTAMP_H__

#include <sys/types.h>

class icmp_tstamp {
public:
	void action(const char* host);
	
private:
	void init_send(char* buf);
	int do_send(int sd, struct in_addr addr, char* buf, int len, u_int16_t seq);
	int do_recv(int sd, struct in_addr addr, char* buf, int len, u_int16_t seq);
	u_int16_t check_sum(const char* buf, int len);
};

#endif // __ICMP_TSTAMP_H__
