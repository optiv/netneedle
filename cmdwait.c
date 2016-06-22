/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "global.h"
#include "block.h"
#include "shell.h"

// what wait time between packets do you want?

int cmdwait(char *args)
{
	if (args == NULL) {
		printf("sleep interval between packets is %i microseconds\n",
		       waittime);

	} else {
		waittime = atoi(args);
	}

	return (0);
}
