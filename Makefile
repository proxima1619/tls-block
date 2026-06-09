all:
	g++ -Wall -O2 -o tls-block tls-block.cpp -lpcap

clean:
	rm -f tls-block
