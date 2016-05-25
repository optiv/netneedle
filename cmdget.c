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
#include "global.h"
#include "block.h"
#include "shell.h"

#define DELIM "\x20\x09"

int makeblock(uint8_t code, uint8_t *data, int len);
int receivedata(int mode);
void updatenonce();

// download a file
int cmdget(char *args) {
	char *source;
	char *destination;

	// if we don't get any filenames, return
	if(args == NULL) {
		return(1);
	}

	source = strtok(args, DELIM);		// source file is everything before the whitespace
	destination = strtok(NULL, DELIM); 	// destination file is whatever they put after the whitespace

	if(destination == NULL) {			// if they don't specify a destination figure out where to put the file
		destination = strrchr(source, '/');	// first, try to put the file in the PWD with the same filename
		if(destination != NULL) {		// we don't want to put the file in the root directory
			*destination++;
		} else {				// if we are using MS Windows, repeat the process
			destination = strrchr(source, '\\');
			if(destination != NULL) {
				*destination++;
			}
		}
		if(destination == NULL) {		// if all else fails, just make them the same
 			destination = source;
		}
	}
	getfilename = (char *)malloc(strlen(destination) + 1);
	memset(getfilename, 0x00, (strlen(destination) + 1));
	strncpy(getfilename, destination, strlen(destination));

	makeblock(CODEGET, (uint8_t *)source, strlen(source));
	receivedata(CMDGET);

	updatenonce();
	return(0);
}
