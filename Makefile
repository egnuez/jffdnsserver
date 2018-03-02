
CC=g++
CFLAGS= -std=c++17
LDFLAGS=-levent

OBJECTS=client.o
BIN=simple_dns_server

all:
	$(CC) $(CFLAGS) $(BIN).cpp -o $(BIN) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f *~ *.o $(BIN)
