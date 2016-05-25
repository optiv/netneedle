CC = gcc
CFLAGS = -O3 
#CFLAGS = -O3 -DSTATIC -static # uncomment for static binary
PROGNAME = needle 

default: all

all: 
	$(CC) $(CFLAGS) -c crypto.c 
	$(CC) $(CFLAGS) -c global.c
	$(CC) $(CFLAGS) -c icmpsend.c
	$(CC) $(CFLAGS) -c block.c
	$(CC) $(CFLAGS) -c cmdhelp.c
	$(CC) $(CFLAGS) -c cmdquit.c
	$(CC) $(CFLAGS) -c cmdexec.c
	$(CC) $(CFLAGS) -c cmdconnect.c 
	$(CC) $(CFLAGS) -c cmdchat.c
	$(CC) $(CFLAGS) -c cmdreceive.c
	$(CC) $(CFLAGS) -c cmdkey.c
	$(CC) $(CFLAGS) -c cmdtoken.c
	$(CC) $(CFLAGS) -c cmdsilent.c
	$(CC) $(CFLAGS) -c cmdget.c
	$(CC) $(CFLAGS) -c cmdput.c
	$(CC) $(CFLAGS) -c cmdwait.c
	$(CC) $(CFLAGS) -c cmdsend.c
	$(CC) $(CFLAGS) -c cmdpayload.c
	$(CC) $(CFLAGS) block.o cmdconnect.o cmdexec.o cmdget.o cmdhelp.o cmdkey.o cmdpayload.o cmdput.o cmdquit.o cmdreceive.o cmdsend.o cmdsilent.o cmdtoken.o cmdwait.o cmdchat.o crypto.o global.o icmpsend.o shell.c -o $(PROGNAME) -lsodium 
	strip $(PROGNAME)

clean: 
	rm -f *.o needle 
