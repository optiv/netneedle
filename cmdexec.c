/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <string.h>
#include "global.h"
#include "block.h"
#include "shell.h"

int makeblock(uint8_t code, uint8_t *data, int len);
int receivedata(int mode);
void updatenonce();

// supply the remote host with a command for execution
int cmdexec(char *args) {
	uint8_t cmdmode;
	// if we don't get any commands to execute, return
	if(args == NULL) {
		return(1);
	}
	
	// remember to set the "silent" bit to tell the other end that we don't want output
	cmdmode = CODEEXEC;
	if(silent) {
		cmdmode = cmdmode | 0x80;
	}
	makeblock(cmdmode, (uint8_t *)args, strlen(args));
	//if we aren't in silent mode listen for output
	if(!silent) {
		receivedata(CMDEXEC);
	}
	updatenonce();
	return(0);
}
