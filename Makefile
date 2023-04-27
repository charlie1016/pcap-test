LDLIBS += -lpcap

all: pcap2

pcap-test: pcap2.cpp

clean:
	rm -f pcap2 *.o

