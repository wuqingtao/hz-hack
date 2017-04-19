// main.cpp

#include "tcp_scan.h"

int main(int argc, char** argv) {
	TcpScan tcpScan;
	tcpScan.scan("127.0.0.1", 22);
}
