/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#define CMDQUIT		1
#define CMDHELP		2
#define CMDEXEC		3
#define CMDCONNECT	4
#define CMDRECEIVE	5
#define CMDPUT		6
#define CMDGET		7
#define CMDHELLO	8
#define CMDKEY		9
#define CMDTOKEN	10
#define CMDSILENT	11
#define CMDSPOOF	12
#define CMDWAIT		13
#define CMDSEND		14
#define CMDPAYLOAD	15
#define CMDCHAT		16

struct cmd {
	char *cmdstr;
	char *description;
	int cmdval;
};

extern const struct cmd cmdtab[];
