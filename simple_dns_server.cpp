
/**
  * Simple DNS Server 
  * 03-2016
  * nunez.emiliano@gmail.com
  **/

#include <event.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <getopt.h>
#include <vector>

#define BUF_SIZE 256

#include "args.h"
#include "Dns.hpp"

dns::Cache cache;

static void udp_cb(const int sock, short int which, void *arg){

	struct sockaddr_in server_sin;
	socklen_t server_sz = sizeof(server_sin);
	uint8_t buf[BUF_SIZE];
	memset(buf, 0, BUF_SIZE);
	
	if (recvfrom(sock, &buf, sizeof(buf) - 1, 0, (struct sockaddr *) &server_sin, &server_sz) == -1) {
		perror("recvfrom()");
		event_loopbreak();
	}

	dns::Resolver resolver(cache);
	
	dns::Package package(buf);
	
	if (arguments.verbose)
		package.prettyPrint();

	resolver.resolve(package);

	if (arguments.verbose)
		package.prettyPrint();

	std::vector<uint8_t> vout = package.dump();
	size_t out_size = vout.size();
	std::string out(vout.begin(), vout.end());

	if (sendto(sock, out.c_str(), out_size, 0, (struct sockaddr *) &server_sin, server_sz) == -1 ) {
		perror("sendto()");
		event_loopbreak();
	}

}

int main(int argc, char **argv) {

	int ret, port, sock, fd[2];

	struct event udp_event;
	struct sockaddr_in sin;

	parse_args (argc, argv);

	if (arguments.verbose){

  		printf (
			"HOST_FILE = %s\n"
        	"VERBOSE = %s\n"
        	"QUIET = %s\n"
        	"NOCACHE = %s\n"
        	"DNS = %s\n",
        	arguments.host_file,
        	arguments.verbose ? "yes" : "no",
        	arguments.quiet ? "yes" : "no",
        	arguments.nocache ? "yes" : "no",
    		arguments.dns
		);

	}

	cache.load(arguments.host_file);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = INADDR_ANY;
	sin.sin_port = htons(1053);
	if (bind(sock, (struct sockaddr *) &sin, sizeof(sin))) {
		perror("bind()");
		exit(EXIT_FAILURE);
	}

	event_init();

	event_set(&udp_event, sock, EV_READ|EV_PERSIST, udp_cb, NULL);
	event_add(&udp_event, 0);

	event_dispatch();
	close(sock);

	return 0;

}