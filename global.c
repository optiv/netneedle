/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <netinet/in.h>
#include "shell.h"

// global variables live here

uint32_t localip;
uint32_t remoteip;
uint32_t token;
uint8_t *key; //delete this later
uint8_t *pk_mine;
uint8_t *sk_mine;
uint8_t *pk_theirs;
uint8_t *sk_theirs;
uint8_t *nonce;
uint8_t *payload;
uint8_t silent;
uint8_t spoof;
uint8_t staticnonce;
uint32_t waittime;
char *getfilename;
uint32_t sendmode;
uint32_t receivemode;
uint16_t tcpport;
struct session *currentsession;

const struct cmd cmdtab[] = {
	{ "quit",	"Quits the program",				CMDQUIT },
	{ "exit",	"Also quits the program",			CMDQUIT },
	{ "help",	"Displays this message",			CMDHELP },
	{ "exec",	"Executes a command on the remote host",	CMDEXEC },
	{ "connect",	"Define the remote host",			CMDCONNECT },
	{ "receive",	"Act as a receiver",				CMDRECEIVE },
	{ "key",	"Set an encryption key",			CMDKEY },
	{ "token",	"Updates the session token",			CMDTOKEN },
	{ "silent",	"Toggels commmand output",			CMDSILENT },
	{ "spoof",	"Designate a fake source address",		CMDSPOOF },
	{ "get",	"Request a file to download",			CMDGET },
	{ "put",	"Upolad a file",				CMDPUT },
	{ "wait",	"Set a wait time between packets",		CMDWAIT },
	{ "send",	"Choose protocol to transmit data",		CMDSEND },
	{ "payload",	"Define a fake TCP payload",			CMDPAYLOAD },	
	{ "chat",	"Send a text message",				CMDCHAT },
	{ NULL, NULL, 0 }
};
