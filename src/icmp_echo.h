// icmp_echo.h

#ifndef __ICMP_ECHO_H__
#define __ICMP_ECHO_H__

#include <stdint.h>

class icmp_echo {
public:
	void action(const char* host);
	
private:
	void initSend(char* buf);
	int doSend(int sd, struct in_addr addr, char* buf, int len, uint16_t seq);
	int doRecv(int sd, struct in_addr addr, char* buf, int len, uint16_t seq, double& rtt);
	uint16_t chksum(const char* buf, int len);
};

#endif // __ICMP_ECHO_H__
