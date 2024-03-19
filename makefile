LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.c
	g++ -o pcap-test.c

clean:
	rm -f pcap-test *.o
