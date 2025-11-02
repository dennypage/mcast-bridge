#CC=clang
#CFLAGS=-Wall -Wextra -g -O2

lib_pcap = -l pcap

all: mcast-bridge mcb-test

protocol_objects = igmp.o mld.o
$(protocol_objects): protocols.h

all_objects = main.o config.o interface.o bridge.o evm.o util.o $(protocol_objects)
$(all_objects): common.h

mcast-bridge: $(all_objects)
	$(CC) -o mcast-bridge -pthread $(all_objects) $(lib_pcap)

.PHONY: clean
clean:
	rm -f mcast-bridge mcb-test $(all_objects)
