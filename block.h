/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <netinet/in.h>
#include "sodium.h"

#define BLOCKSIZE 0x100
#define SIGNEDBLOCKSIZE (BLOCKSIZE + crypto_box_BOXZEROBYTES)

#define CODEERROR		0x00
#define CODEHELLO		0x01
#define CODEEXEC		0x02
#define CODEEXECQUITE		0x03
#define CODEPUT			0x04
#define CODEGET			0x05
#define CODERESPONSE		0x06
#define CODETOKEN		0x07
#define CODECHAT		0x08

#define DEFAULTPAYLOAD "GET / HTTP/1.1\r\nHost: www.google.com\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.111 Safari/537.36\r\nAccept-Encoding: gzip, deflate, sdch\r\nAccept-Language: en-US,en;q=0.8\r\n"

struct blockhdr {
	uint8_t code;
	uint8_t id;
	uint32_t token;
	uint32_t size;
};

struct datablock {
	struct blockhdr header;
	uint8_t data[BLOCKSIZE - sizeof(struct blockhdr)];
};
