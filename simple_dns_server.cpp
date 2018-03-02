
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

static void udp_cb(const int sock, short int which, void *arg){

	struct sockaddr_in server_sin;
	socklen_t server_sz = sizeof(server_sin);
	uint8_t buf[BUF_SIZE];
	memset(buf, 0, BUF_SIZE);
	
	if (recvfrom(sock, &buf, sizeof(buf) - 1, 0, (struct sockaddr *) &server_sin, &server_sz) == -1) {
		perror("recvfrom()");
		event_loopbreak();
	}

	dns::Cache cache;
	cache.load(arguments.host_file);
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
/*
	dns::Question* question1 = new dns::Question("www.site1.com", 1, 1);
    dns::Question* question2 = new dns::Question("www.site2.com", 1, 1);
	dns::Question* question3 = new dns::Question("www.site1.com", 1, 1);
    dns::Question* question4 = new dns::Question("www.site3.com", 1, 1);
   
	dns::Answer* answer1 = new dns::A_Answer("www.site1.com", 1, 1, 60);
    answer1->setRData(1,2,3,4);
    dns::Answer* answer2 = new dns::A_Answer("www.site2.com", 1, 1, 120);
    answer2->setRData(1,2,3,5);

    dns::Cache cache;
    cache.load("/etc/hosts");
    cache.set(question1, answer1);
    cache.set(question2, answer2);

    std::optional<dns::Answer*> res1 = cache.get(question1);
    std::optional<dns::Answer*> res2 = cache.get(question2);
	std::optional<dns::Answer*> res3 = cache.get(question3);
    std::optional<dns::Answer*> res4 = cache.get(question4);

	if(res1)
    	std::cout << (*res1)->rDataToStr() << std::endl;
    else
		std::cout << "q1 not found" << std::endl;
	
	if(res2)
		std::cout << (*res2)->rDataToStr() << std::endl;
	else
		std::cout << "q2 not found" << std::endl;

	if(res3)
		std::cout << (*res3)->rDataToStr() << std::endl;
	else
		std::cout << "q3 not found" << std::endl;

	if(res4)
		std::cout << (*res4)->rDataToStr() << std::endl;
	else
		std::cout << "q4 not found" << std::endl;
*/
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