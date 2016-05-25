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
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "global.h"
#include "block.h"
#include "shell.h"

#define DELIM "\x20\x09"

int makeblock(uint8_t code, uint8_t *data, int len);
int receivedata(int mode);
void updatenonce();

// upload a file
int cmdput(char *args) {
	char *source;
	char *destination;
	uint32_t filenamelen;
	uint32_t one = 1;
        struct stat sd;
        int fd;
        uint8_t *filebuf;
	

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

	filenamelen = strlen(destination) + 1;
	if(filenamelen & one) {	// adding one byte of padding to deal with memory alignment issues
		filenamelen++;
	}

	

        fd = open(source, O_RDONLY);
        if(fd < 0) {
              	perror("can't open file\n"); 
                return(0);
        }
        if(fstat(fd, &sd) == 0) {
                filebuf = (uint8_t *)malloc(sd.st_size + filenamelen);
                if(filebuf == NULL) {
                        perror("can't allocate memory");
                        exit(1);
                }
		memset(filebuf, 0x00, sd.st_size + filenamelen);
		memcpy(filebuf, destination, strlen(destination));
                if(read(fd, filebuf + filenamelen, sd.st_size) > 0) {
			makeblock(CODEPUT, filebuf, sd.st_size + filenamelen);
		}
        	free(filebuf);
        } 
	close(fd);
	updatenonce();
	
	return(0);
}
