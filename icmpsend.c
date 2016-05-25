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
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include "global.h"

#define BUFLEN 1024
#define RETRIES 3
#define TIMEOUT 5 //retransmussion timeout in seconds

uint8_t getrandom8();
int encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *key,
  uint8_t *iv, uint8_t *ciphertext);

int hexdump(uint8_t *buf, int buflen) {
        int i;
        int pos;

        pos = 0;
        printf("\n");
        for(i = 0; i < buflen; i++) {
                printf("%02x ", buf[i]);
                pos++;
                if(pos == 16) {
                        printf("\n");
                        pos = 0;
                }
        }
        printf("\n");
        return(0);
}


struct pseudohdr {
	uint32_t saddr;
	uint32_t daddr;
	uint8_t unused;
	uint8_t protocol;
	uint16_t len;
};

u_int16_t in_cksum(u_int16_t * addr, int len)
{
    register int nleft = len;
    register u_int16_t *w = addr;
    register int sum = 0;
    u_short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(u_char *) (&answer) = *(u_char *) w;
        sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
    sum += (sum >> 16);         /* add carry */
    answer = ~sum;              /* truncate to 16 bits */
    return (answer);
}


int sendicmp(uint32_t s_ip, uint32_t d_ip, uint16_t seq, uint16_t id, uint16_t icmpid) {
	struct iphdr *ip;
	struct icmphdr *icmp;
	struct sockaddr_in sin;
	struct timeval tv;

	uint8_t *pkt;
	uint8_t *payload;
	uint16_t randbyte;

	int one = 1;
	int pktlen;
	int sock;

	randbyte = getrandom8();	// populate the higher 8 bits with random data
	randbyte = randbyte << 8;
	id = id | randbyte;
	
	pktlen = sizeof(struct iphdr) + sizeof(struct icmphdr) + 56;
	
	pkt = (uint8_t *)malloc(pktlen);
	if(pkt == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	memset(pkt, 0x00, pktlen);
	payload = pkt + sizeof(struct iphdr) + sizeof(struct icmphdr);
	gettimeofday(&tv, NULL);
	memcpy(payload, &tv.tv_sec, sizeof(tv.tv_sec));
	memcpy(payload + 8, &tv.tv_usec, sizeof(tv.tv_sec));
	memcpy(payload + 16, "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37", 40); 
	
	
	ip = (struct iphdr *)pkt;
	icmp = (struct icmphdr *) (pkt + sizeof(struct iphdr));
	
	icmp->type = ICMP_ECHO;
	icmp->un.echo.sequence = htons(seq); 
	icmp->un.echo.id = icmpid;
	icmp->checksum = in_cksum(((uint16_t *)icmp), (sizeof(struct icmphdr)) +  56);
	
	ip->saddr = s_ip;
	ip->daddr = d_ip;

	ip->version = 0x04;
	ip->ihl = 0x05; 		// minimum value is 5
	ip->ttl = 0x40;			
	ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + 56);
	ip->protocol = 0x01;		// 0x01 == ICMP
	ip->id = htons(id);
	if(ip->id == 0x0000) {   	// IP ID can't equal 0x00
		ip->id = 0xb700;
	}
	ip->frag_off = htons(IP_DF);
	ip->check = 0x00;		// probably unnecessary
	ip->check = in_cksum((u_int16_t *)pkt, sizeof(struct iphdr));

	sin.sin_family = AF_INET;
	sin.sin_port = 0x00;
	sin.sin_addr.s_addr = d_ip;	
	
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sock < 0) {
		perror("can't open socket");
		exit(1);
	}

	if(setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		perror("setting socket options");
		exit(1);
	}

	if(sendto(sock, pkt, pktlen, 0, (struct sockaddr *) &sin, sizeof(struct sockaddr)) < 0) {
		perror("sending packet");
		exit(1);
	}
	close(sock);
	free(pkt);	
	return(0);
}



int sendtcp(u_int32_t s_ip, u_int32_t d_ip, u_int16_t sport,
                u_int16_t dport, unsigned char *buf, u_int16_t buflen,
                int seqoffset, int acknumber, uint16_t id)
{
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct sockaddr_in sin;
    struct pseudohdr *pseudo;
    unsigned char *pkt;
    uint16_t randbyte;
    int one = 1;
    int pktlen;
    int sock;

    pktlen = sizeof(struct iphdr) + sizeof(struct tcphdr) + buflen;

    pkt = (unsigned char *) malloc(pktlen);
    if (pkt == NULL) {
        perror("can't allocate memory");
        exit(1);
    }
    memset(pkt, 0x00, pktlen);
    memcpy(pkt + sizeof(struct iphdr) + sizeof(struct tcphdr), buf,
           buflen);

    ip = (struct iphdr *) pkt;
    tcp = (struct tcphdr *) (pkt + sizeof(struct iphdr));
    pseudo =
        (struct pseudohdr *) (pkt + (sizeof(struct iphdr) -
                                     sizeof(struct pseudohdr)));

    pseudo->saddr = s_ip;
    pseudo->daddr = d_ip;
    pseudo->protocol = 6;
    pseudo->len = htons(sizeof(struct tcphdr) + buflen);

    tcp = (struct tcphdr *) (pkt + sizeof(struct iphdr));
    tcp->source = htons(sport);
    tcp->dest = htons(dport);
    tcp->seq = htonl(seqoffset);
    tcp->ack_seq = htonl(acknumber);
    tcp->psh = 1;
    tcp->ack = 1;
    tcp->window = htons(400);
    tcp->urg_ptr = 0;
    tcp->doff = 5;
    tcp->check = in_cksum((u_int16_t *) pseudo, (sizeof(struct tcphdr) +
                                                 sizeof(struct pseudohdr) +
                                                 buflen));

    ip->saddr = s_ip;
    ip->daddr = d_ip;
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 123;
    ip->tot_len =
        htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + buflen);
    randbyte = getrandom8();
	randbyte = randbyte << 8;
    ip->id = htons(id | randbyte); 
    ip->protocol = 0x06;
    ip->check = 0;
    ip->check = in_cksum((u_int16_t *) pkt, sizeof(struct iphdr));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(dport);
    sin.sin_addr.s_addr = d_ip;

    sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) {
        perror("can't open socket");
        exit(1);
    }

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setting socket options");
        exit(1);
    }
    if (sendto
        (sock, pkt, pktlen, 0, (struct sockaddr *) &sin,
         sizeof(struct sockaddr)) < 0) {
        perror("sending packet");
        exit(1);
    }
    close(sock);
    return (0);
}


int connecttcp(uint32_t host, uint16_t port) {
	int sock;
	struct sockaddr_in sa;
	

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
		return(0);
	}
	
	sa.sin_family = AF_INET;
	memcpy(&sa.sin_addr.s_addr, &host, 4);
	sa.sin_port = htons(port);
	connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_in));

	return(sock);
}

int sendtcpid(uint32_t s_ip, uint32_t d_ip, uint16_t dport, uint8_t *buf, int buflen) {
	int sock;
	int packetlen;
	int i;
	int payloadpos;
	uint32_t seq;
	uint32_t ack;
	uint8_t *packet;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct timeval tv;
	pid_t procid;

	procid = fork();

	packet = (uint8_t *)malloc(BUFLEN);
	if(packet == NULL) {
		perror("can't allocate memory\n");
		exit(1);
	}
	ip = (struct iphdr *)packet;
	tcp = (struct tcphdr *)(packet + sizeof(struct iphdr));
	
	if(procid == 0) {	// if we are the child process, connect to the server
		usleep(10000);	// give parent process time to get ready
		sock = connecttcp(d_ip, dport);	
		for(packetlen = 0;packetlen <= 0; packetlen = read(sock, packet, BUFLEN)); 
		
		return(0);
	}

	
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(sock < 0) {
		perror("can't open raw socket\n");
		return(0);
	}
	tv.tv_sec = 2; // give a 2 second timeout on read 
	tv.tv_usec = 0; 
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
	
	ack = 0;
	seq = 0;
	for(packetlen = 0; packetlen >= 0 ; packetlen = read(sock, packet, BUFLEN)) {	
		if((tcp->th_flags == 0x0012) && (ip->saddr == d_ip)) {
			ack = ntohl(tcp->ack_seq);
                        seq = ntohl(tcp->seq);
		}
	}
	payloadpos = 0;
	for(i = 0; i < buflen; i++) {
	
		sendtcp(ip->daddr, ip->saddr, htons(tcp->dest), htons(tcp->source), payload + payloadpos++, 1, ack + i, seq, buf[i]);
	
		for(packetlen = 0; packetlen >= 0 ; packetlen = read(sock, packet, BUFLEN)) {
			if(tcp->th_flags == (TH_ACK) && (ip->saddr == d_ip)) {
				break;
			}
		}
		if(payloadpos > strlen((char *)payload)) {		// replay the payload, if we get to the end
			payloadpos = 0;
		}
	}
	

	return(0);
}

int sendpingid(uint32_t s_ip, uint32_t d_ip, uint8_t *buf, int buflen) {
	int i;
	int sock;
	struct icmphdr *icmp;
	struct iphdr *ip;
	uint8_t *packet;
	uint16_t id;
	uint16_t icmpid;
	int packetlen;
	int retry = RETRIES;
	float percentcomplete;
	struct timeval tv;

	// buffer length is 0xff, because we are only sending
	// one byte at a time, and the maximum value of a byte
	// is 0xff

	icmpid = getpid(); // make this a random number later
	packet =  (uint8_t *)malloc(BUFLEN);
	if(packet == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	
	ip = (struct iphdr *)packet;
	icmp = (struct icmphdr *)(packet + sizeof(struct iphdr));

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sock < 0) {
		perror("can't open ICMP socket");
		exit(1);
	}
	tv.tv_sec = TIMEOUT;	//timeout while waiting for echo responses
	tv.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));

	for(i = 0; i < buflen; i++) {
		if(retry == 0) {
			perror("Nobody is home");
			exit(1);
		}
		id = 0;
		id |= buf[i];  
	
		if(waittime > 0) {
			usleep(waittime);
		}
		sendicmp(s_ip, d_ip, i + 1, id, icmpid);
		if(spoof) {
			percentcomplete = ((float)i / (float)buflen) * 100;
			printf("%c%c%3.0f%% complete", 0x1b, 0x38, percentcomplete);
		}
		else {
			for(packetlen = 0; packetlen >=0 ; packetlen = read(sock, packet, BUFLEN)) {
				if((d_ip == ip->saddr) && (icmp->un.echo.sequence == ntohs(i + 1))) {
					retry = RETRIES;
					break;
				}
			}
			if(packetlen < 0) {
				retry--; // if "read" times out and returns -1, we try again
				i--;     // trying again means we want to try the last byte 
			}
		}
	}
	if(silent) {
		printf("\n");
	}
	free(packet);
	return(0);
}


