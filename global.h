/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <netinet/in.h>
#include <sodium.h>

//global variables live here and in the corresponding c file
extern uint32_t localip;
extern uint32_t remoteip;
extern uint32_t token;
extern uint32_t receivemode;
extern uint32_t sendmode;
extern uint8_t *key;
extern uint8_t *pk_mine;
extern uint8_t *sk_mine;
extern uint8_t *pk_theirs;
extern uint8_t *sk_theirs;
extern uint8_t *nonce;
extern uint8_t silent;
extern uint8_t spoof;
extern uint8_t staticnonce;
extern uint8_t *payload;
extern uint32_t waittime;
extern char *getfilename;
extern uint16_t tcpport;
extern struct session *currentsession;

struct session {
	uint32_t token;
	uint8_t padding[crypto_box_NONCEBYTES - 4];
};
