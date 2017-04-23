cc = gcc
exe = hztrack
obj = main.o host_parse.o icmp_echo.o tcp_full.o

$(exe): $(obj)
	$(cc) -o $(exe) $(obj)

main.o: main.cc
	$(cc) -c main.cc

host_parse.o: host_parse.cc
	$(cc) -c host_parse.cc

icmp_echo.o: icmp_echo.cc
	$(cc) -c icmp_echo.cc

tcp_full.o: tcp_full.cc
	$(cc) -c tcp_full.cc

clean:
	rm $(exe) $(obj)
