/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include "global.h"

// take a hostname and IP and resolve it. IPV4 only!
uint32_t resolvehost4(char *host)
{
	uint32_t ip;
	struct hostent *hp;
	ip = inet_addr(host);
	if (ip == INADDR_NONE) {
#ifndef STATIC			// gethostbyname() doesn't like static compilation
		hp = gethostbyname(host);
		memcpy(&ip, hp->h_addr, 4);
#endif
	}
	return (ip);
}

// if we want to generate packets, we have to know our own source address
uint32_t getlocalip(uint32_t dest)
{
	int sock;
	struct sockaddr_in sa;
	struct sockaddr_in local;
	int sockaddrlen;

	memset(&sa, 0x00, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = 0xb7;
	memset(&sa.sin_addr, dest, 4);
	memset(&local, 0x00, 16);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		perror("can't create socket");
		exit(1);
	}

	connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_in));

	sockaddrlen = sizeof(struct sockaddr_in);
	getsockname(sock, (struct sockaddr *)&local,
		    (socklen_t *) & sockaddrlen);

	return (local.sin_addr.s_addr);
}

// this function defines the destination address
int cmdconnect(char *args)
{
	uint8_t *octet;

	if (args == NULL) {
		printf("Please specify a destination host\n");
		return (1);
	}
	remoteip = resolvehost4(args);
	localip = getlocalip(remoteip);
	spoof = 0;
	octet = (uint8_t *) & remoteip;
	printf("Connecting to %i.%i.%i.%i\n", octet[0], octet[1], octet[2],
	       octet[3]);
	octet = (uint8_t *) & localip;
	printf("Using local IP to %i.%i.%i.%i\n", octet[0], octet[1], octet[2],
	       octet[3]);
	return (0);
}

// if you don't want to use your own source address, this function
// lets you do that.
int cmdspoof(char *args)
{
	uint8_t *octet;

	if (args == NULL) {
		printf("Please specify a source IP\n");
		return (1);
	}

	localip = resolvehost4(args);
	octet = (uint8_t *) & localip;
	spoof = 1;		// let the rest of the program know we are spoofing an IP
	silent = 1;		// go into silent mode because we can't see the output anyway
	printf("Using local IP to %i.%i.%i.%i\n", octet[0], octet[1], octet[2],
	       octet[3]);
	return (0);
}
