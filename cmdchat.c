/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "global.h"
#include "block.h"
#include "shell.h"

int cmdreceive(char *args);
int makeblock(uint8_t code, uint8_t * data, int len);
int receivedata(int mode);

#define INPUTBUFFERSIZE 0xffff

// send a text message
int cmdchat(char *args)
{
	uint8_t cmdmode;
	int status;
	char *inbuf;
	pid_t procid;

	// remember to set the "silent" bit to tell the other end that we don't want output
	cmdmode = CODECHAT;
	if (args != NULL) {
		if (silent) {
			cmdmode = cmdmode | 0x80;
		}
		makeblock(cmdmode, (uint8_t *) args, strlen(args));
	} else {
		inbuf = malloc(INPUTBUFFERSIZE);
		if (inbuf == NULL) {
			perror("can't allocate memory");
			exit(0);
		}

		procid = fork();
		if (procid == 0) {
			cmdreceive(NULL);
		}
		for (;;) {
			printf("CHAT] ");
			if (fgets(inbuf, INPUTBUFFERSIZE, stdin) > 0) {
				if (!strncmp(inbuf, "quit", 4)) {
					kill(procid, 9);
					wait(&status);
					return (0);
				}
				makeblock(cmdmode, (uint8_t *) inbuf,
					  strlen(inbuf));

			} else {
				return (0);
			}
		}
	}

	return (0);
}
