/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include "shell.h"

// display a help message
int cmdhelp() {
	int i;
	printf("Command\t\tFunction\n");
	for(i = 0; cmdtab[i].cmdval != 0; i++) {
		printf("%s\t\t%s\n", cmdtab[i].cmdstr, cmdtab[i].description);
	}
	return(0);
}
