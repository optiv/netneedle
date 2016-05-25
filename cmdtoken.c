/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <string.h>
#include <sodium.h>
#include "shell.h"
#include "global.h"
#include "block.h"

int makeblock(uint8_t code, uint8_t *data, int len);
int receivedata(int mode);

// set a new nonce

void updatenonce() {
	if(staticnonce == 0) {
		currentsession->token = ntohl(currentsession->token) + 1;
		currentsession->token = htonl(currentsession->token);
	}
}


int cmdtoken(char *args) {
	if(args == NULL) {
		memset(nonce, 0x0, crypto_box_NONCEBYTES);
		makeblock(CODETOKEN, (uint8_t *)"AAAAAAAA", 8);
		receivedata(CMDTOKEN);
	} else if(!strncmp(args, "static", 6)) {
		printf("nonce is now static\n");
		staticnonce = 1;
	} else if(!strncmp(args, "dynamic", 7)) {
		printf("nonce is now dynamic\n");
		staticnonce = 0;
	}
	return(0);
}
