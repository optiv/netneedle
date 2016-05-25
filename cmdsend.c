/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include "global.h"
#include "block.h"
#include "shell.h"

// how do we send the data? ICMP, TCP or something else?  

int cmdsend(char *args) {
	char *portstr;
	if(args == NULL) {				// display current send mode
		if(sendmode == IPPROTO_TCP) {
			printf("Transmit mode: TCP port %i\n", tcpport);
		} else {
			printf("Transmit mode: ICMP\n");
		}
		return(0);
	}
	if(!strncasecmp(args, "TCP", 3)) {
		sendmode = IPPROTO_TCP;
		portstr = strchr(args, 0x20);		// find the substring with the port
		if(portstr == NULL) {			// if no port is spedified, go with default
			portstr = "80";	 		// default port == 80
		}
		tcpport = (uint16_t)strtol(portstr, NULL, 10);
	}
	else {
		sendmode = IPPROTO_ICMP;		// ICMP should be the default
	}

	return(0);
}
