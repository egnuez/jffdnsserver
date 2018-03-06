
CC=g++
CFLAGS= -std=c++17
LDFLAGS=-levent

OBJECTS=client.o
BIN=simple_dns_server
TESTS=simple_dns_tests

all:
	$(CC) $(CFLAGS) $(BIN).cpp -o $(BIN) $(LDFLAGS)

tests:
	$(CC) $(CFLAGS) $(TESTS).cpp -o $(TESTS) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f *~ *.o *.gch $(BIN) $(TESTS)
