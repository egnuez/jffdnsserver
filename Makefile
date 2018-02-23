
CC=g++
CFLAGS=-Wall
LDFLAGS=-levent

OBJECTS=client.o
BIN=simple_dns_server

all:
	$(CC) $(BIN).cpp -o $(BIN) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f *~ *.o $(BIN)
