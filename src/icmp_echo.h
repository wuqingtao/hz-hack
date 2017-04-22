// icmp_echo.h

#ifndef __ICMP_ECHO_H__
#define __ICMP_ECHO_H__

#include <stdint.h>

class IcmpEcho {
public:
	void action(const char* host);
	
private:
	uint16_t chksum(const char* buf, int len);
};

#endif // __ICMP_ECHO_H__
