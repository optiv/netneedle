/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include "block.h"
#include "global.h"

// function prototypes go here

int sendpingid(uint32_t s_ip, uint32_t d_ip, uint8_t *buf, int buflen);
int sendtcpid(uint32_t s_ip, uint32_t d_ip, uint16_t dport, uint8_t *buf, int buflen);
int encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *pk, uint8_t *sk, uint8_t *nonce, uint8_t *ciphertext);

// This function takes a command code, associated data and the length
// of that data and makes a block for encryption and transmission

int makeblock(uint8_t code, uint8_t *data, int len, uint8_t *outputblock) {
	unsigned int msgsize;
	int numberofblocks;
	struct datablock *db;
	int blockoffset;
	int i;
	int m;
	int payloadsize;

	payloadsize = BLOCKSIZE - sizeof(struct blockhdr);
	
	numberofblocks = (len / payloadsize);
	m = len % payloadsize;
	if(m) numberofblocks++;
	
	
	msgsize = numberofblocks * SIGNEDBLOCKSIZE;
	outputblock = (uint8_t *)malloc(msgsize + crypto_box_BOXZEROBYTES);
	if(outputblock == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	memset(outputblock, 0x00, msgsize + crypto_box_BOXZEROBYTES);

	db = (struct datablock *)malloc(BLOCKSIZE);
	if(db == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	memset(db, 0x00, BLOCKSIZE);
	for(blockoffset = 0 ; blockoffset < len ; blockoffset += payloadsize) {
		for(i = 0; i < numberofblocks; i++) {
			db->header.code = code;
        	        db->header.token = htonl(token);
		
        	        db->header.size = htonl(len);
			
			memcpy((int8_t *)db->data, (int8_t *)(data + blockoffset), payloadsize);
			blockoffset += payloadsize;
			
			encrypt((uint8_t *)db, BLOCKSIZE, pk_theirs, sk_mine, nonce, outputblock + (i * SIGNEDBLOCKSIZE));
		}
	}

	if(sendmode == IPPROTO_TCP) {
		sendtcpid(localip, remoteip, tcpport, (uint8_t *)outputblock, msgsize);
	} else {
		sendpingid(localip, remoteip, (uint8_t *)outputblock, msgsize);
	}

	free(db);
	free(outputblock);

	return(0);
}

