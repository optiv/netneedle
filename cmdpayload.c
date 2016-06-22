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
#include "global.h"
#include "block.h"

#define BUFSIZE 0x100

int cmdpayload(char *args)
{
	int m;
	int payloadsize;
	int numberofblocks;

	//payload = args;

	if ((args == NULL) || (strlen(args) == 0)) {	// this is what we do if we get no parameters
		return (0);
	}

	if ((payload != (uint8_t *) DEFAULTPAYLOAD) && (payload != NULL)) {	// if we are changing the payload, free the old one
		free(payload);
	}

	numberofblocks = ((strlen(args) + 1) / BUFSIZE);	// Trying to keep heap boundries in order
	m = strlen(args) % BUFSIZE;
	if (m)
		numberofblocks++;
	payloadsize = numberofblocks * BUFSIZE;

	payload = malloc(payloadsize);	//  allocate space for the payload and copy to it
	if (payload == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	memcpy(payload, args, strlen(args));
	payload[strlen(args)] = 0x00;

	return (0);
}
