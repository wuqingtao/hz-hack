cc = g++
exe = hztrack
obj = main.o host_parser.o icmp_echo.o tcp_full.o

$(exe): $(obj)
	$(cc) -o $(exe) $(obj)

main.o: main.cpp
	$(cc) -c main.cpp

host_parser.o: host_parser.cpp
	$(cc) -c host_parser.cpp

icmp_echo.o: icmp_echo.cpp
	$(cc) -c icmp_echo.cpp

tcp_full.o: tcp_full.cpp
	$(cc) -c tcp_full.cpp

clean:
	rm $(exe) $(obj)
