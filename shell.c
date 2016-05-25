/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <string.h>
#include "block.h"
#include "shell.h"
#include "global.h"

#define INPUTBUFFERSIZE 0xffff	// how much text can we read at once
#define PROMPTSTR "] "		// what should the prompt look like

// function prototypes go here
int cmdquit();
int cmdhelp();
int cmdexec(char *args);
int cmdconnect(char *args);
int cmdreceive(char *args);
int cmdspoof(char *args);
int cmdkey(char *args);
int cmdtoken(char *args);
int cmdsilent(char *args);
int cmdget(char *args);
int cmdput(char *args);
int cmdwait(char *args);
int cmdsend(char *args);
int cmdchat(char *args);
int cmdpayload(char *args);


// This function takes a command line that someone enters and tries
// to process it.

int interpretcmd(char *line) {
	int i;
	int cmdval = 0;
	char *cmd;
	char *args;
	char *end;

	cmd = line;
	// we want to separate the command from its parameters
	while(isblank(*cmd)) // the "command" starts at the first non-blank character
		*cmd++;
	
	end = cmd + (strlen(cmd)) - 1;
	while(end > cmd && isspace(*end)) {
		*end = 0x00;
		end--;
	}
	
	args = strchr(cmd, 0x20); // the arguments for the command start after the first space
	// if args aren't null, clean up trailing whitespace
	if(args != NULL) { 
		while(isblank(*args)) {
			*args++;
		}
	}

	for(i = 0; cmdtab[i].cmdstr != NULL; i++) {
		if(!strncmp(cmd, cmdtab[i].cmdstr, strlen(cmdtab[i].cmdstr))) {
			cmdval = cmdtab[i].cmdval;
			break;
		}
	}

	switch(cmdval) {
		case CMDQUIT:
			cmdquit();
			break;
		case CMDHELP:
			cmdhelp();
			break;
		case CMDEXEC:
			cmdexec(args);
			break;
		case CMDCONNECT:
			cmdconnect(args);
			break;
		case CMDRECEIVE:
			cmdreceive(args);
			break;
		case CMDKEY:
			cmdkey(args);
			break;
		case CMDTOKEN:
			cmdtoken(args);
			break;
		case CMDSILENT:
			cmdsilent(args);
			break;
		case CMDSPOOF:
			cmdspoof(args);
			break;
		case CMDGET:
			cmdget(args);
			break;
		case CMDPUT:
			cmdput(args);
			break;
		case CMDWAIT:
			cmdwait(args);
			break;
		case CMDSEND:
			cmdsend(args);
			break;
		case CMDPAYLOAD:
			cmdpayload(args);
			break;
		case CMDCHAT:
			cmdchat(args);
			break;
		default:
			if(strlen(cmd) > 1) { // only present error message if they tried to type something
				printf("Command not found\n");
			}
	}
	return(0);
}

int shell() {
	char *buf;

	buf = (char *)malloc(INPUTBUFFERSIZE);
	if(buf == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	for(;;) {
		memset(buf, 0x00, INPUTBUFFERSIZE);
		printf("%s", PROMPTSTR);		// display the prompt and read user input
		if(fgets(buf, INPUTBUFFERSIZE, stdin) > 0) {
			interpretcmd(buf);	
		} else {
			return(0);
		}
		
	}
	
	return(0);
}

int usage(char *argzero) {
	printf("Usage: %s [-h] [-k public key | private Key | their public key ] -s [script file]\n", argzero);
	printf("\t-h\tDisplay help message\n");
	printf("\t-k\tGo into \"listen\" mode with a defined set of keys\n");
	printf("\t-s\tScript file with commands for execution\n");

	return(0);
	
}

int main(int argc, char *argv[]) {
	FILE *file;
	char *scriptfile;
	char *linebuf;
	int runascript = 0;
	int c;
	int i;
	int daemon = 0;
	int arglen;
	
	sendmode = IPPROTO_ICMP;
	receivemode = IPPROTO_ICMP;
	tcpport = 80;
	silent = 0; 
	staticnonce = 0;
	payload = (uint8_t *)DEFAULTPAYLOAD;
	nonce = (uint8_t *)malloc(crypto_box_NONCEBYTES);
	if(nonce == NULL) {
		perror("can't allocate memory");	
		exit(1);
	}
	memset(nonce, 0x00, crypto_box_NONCEBYTES);
	currentsession = (struct session *)nonce;

	while((c = getopt(argc, argv, "hs:k:m:")) != -1) {
		switch(c) {
			case 'h':
				usage(argv[0]);
				printf("Here is a summary of available commands:\n");
				cmdhelp();
				return(0);
				break;
			case 's':
				scriptfile = optarg;
				if(scriptfile == NULL) {
					fprintf(stderr, "-s requires the name of a file to execute\n");
					return(1);
				}
				runascript++;
				break;
			case 'k':
				daemon++;
				// get rid of the trailing \n we get from the command line
				if(optarg[strlen(optarg)] == '\n') {
					optarg[strlen(optarg)] = 0x00;
				}
				cmdkey(optarg);
				break;
			default:
				break;
		}
	}
	if(runascript) {
		file = fopen(scriptfile, "rb");
		if(file <= 0) {
			fprintf(stderr, "can't open %s\n", scriptfile);
			exit(1);
		}	
		linebuf = (char *)malloc(INPUTBUFFERSIZE);
		if(linebuf == NULL) {
			perror("can't allocate memory");
			exit(1);
		}
		while(fgets(linebuf, INPUTBUFFERSIZE, file) != NULL) {
			if(strlen(linebuf) > 0) {
				interpretcmd(linebuf);
			}
		}
		fclose(file);
	}

	if(daemon) {			// run as a background process
		if(fork()) {		// if we are the parent process, exit
			return(0);
		}
		for(i = 1; i < argc; i++) {
			arglen = strlen(argv[i]);
			for(c = 0; c < arglen; c++) {
				argv[i][c] = 0x00;
			}
		}
		
		cmdreceive(NULL); //if we are the child process go into receive mode
	}
	
	shell();
	return (0);
}
