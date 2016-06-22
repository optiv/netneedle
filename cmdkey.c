#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sodium.h>
#include "cmdkey.h"
#include "global.h"

#define KEYBUFSIZE 256
#define KEYLEN 32		// move this to global.h

const struct keycmd keycmdtab[] = {
	{"new", KEYCMDNEW},
	{"view", KEYCMDVIEW},
	{"public", KEYCMDPUBLIC},
	{"private", KEYCMDPRIVATE},
	{"client", KEYCMDCLIENT},
	{NULL, 0}
};

char *findarg(char *str)
{
	char *rstr;

	rstr = strchr(str, 0x20);
	if (rstr != NULL) {
		while (isblank(*rstr)) {
			*rstr++;
		}
	}
	return (rstr);
}

// convert ascii hex string to binary 
uint8_t *extractkey(char *str)
{
	int i;
	uint8_t *rkey;
	char bytebufstr[3];

	if (str == NULL) {
		return (0);
	}

	if (strlen(str) != KEYLEN * 2) {
		return (0);
	}

	bytebufstr[2] = 0;

	rkey = (uint8_t *) malloc(KEYLEN);
	if (rkey == NULL) {
		perror("can't allocate memory");
		exit(1);
	}

	for (i = 0; i < KEYLEN; i++) {
		bytebufstr[0] = str[i * 2];
		bytebufstr[1] = str[(i * 2) + 1];
		rkey[i] = strtol(bytebufstr, NULL, 16);
	}
	return (rkey);
}

// define public/private keys or make a new keypair
int cmdkey(char *args)
{
	int len = KEYBUFSIZE;
	int i;
	int cmdval = 0;
	char *keystr;
	uint8_t *keybuf;

	for (i = 0; keycmdtab[i].cmdstr != NULL; i++) {
		if (!strncmp
		    (args, keycmdtab[i].cmdstr, strlen(keycmdtab[i].cmdstr))) {
			cmdval = keycmdtab[i].cmdval;
			break;
		}
	}

	switch (cmdval) {
	case KEYCMDNEW:
		if ((pk_mine != NULL) && (sk_mine != NULL)) {
			free(pk_mine);
			free(sk_mine);
		}
		pk_mine = (uint8_t *) malloc(KEYLEN);
		if (pk_mine == NULL) {
			perror("can't allocate memory");
			exit(1);
		}
		sk_mine = (uint8_t *) malloc(KEYLEN);
		if (sk_mine == NULL) {
			perror("can't allocate memory");
			exit(1);
		}
		crypto_box_keypair(pk_mine, sk_mine);
		break;
	case KEYCMDVIEW:
		if (pk_mine != NULL) {
			printf("PUBLIC KEY:\t");
			for (i = 0; i < KEYLEN; i++) {
				printf("%02x", pk_mine[i]);
			}
			printf("\n");
		}
		if (sk_mine != NULL) {
			printf("PRIVATE KEY:\t");
			for (i = 0; i < KEYLEN; i++) {
				printf("%02x", sk_mine[i]);
			}
			printf("\n");
		}
		if (pk_theirs != NULL) {
			printf("CLIENT KEY:\t");
			for (i = 0; i < KEYLEN; i++) {
				printf("%02x", pk_theirs[i]);
			}
			printf("\n");
		}
		break;
	case KEYCMDPUBLIC:
		keystr = findarg(args);
		if (keystr != NULL) {
			keybuf = extractkey(keystr);
			if (pk_mine != NULL) {
				free(pk_mine);
			}
			pk_mine = keybuf;
		}
		break;
	case KEYCMDPRIVATE:
		keystr = findarg(args);
		if (keystr != NULL) {
			keybuf = extractkey(keystr);
			if (sk_mine != NULL) {
				free(sk_mine);
			}
			sk_mine = keybuf;
		}
		break;
	case KEYCMDCLIENT:
		keystr = findarg(args);
		if (keystr != NULL) {
			keybuf = extractkey(keystr);
			if (pk_theirs != NULL) {
				free(pk_theirs);
			}
			pk_theirs = keybuf;
		}
		break;
	default:
		if (strlen(args) == (KEYLEN * 6)) {
			keystr = malloc((KEYLEN * 2) + 1);
			if (keystr == NULL) {
				perror("can't allocate memory");
				exit(1);
			}
			memcpy(keystr, args, KEYLEN * 2);
			keystr[(KEYLEN * 2) + 1] = 0x00;
			pk_mine = extractkey(keystr);
			memcpy(keystr, args + (KEYLEN * 2), KEYLEN * 2);
			sk_mine = extractkey(keystr);
			memcpy(keystr, args + (KEYLEN * 4), KEYLEN * 2);
			pk_theirs = extractkey(keystr);
			free(keystr);
		}
		printf("\n");
	}

	if ((args == NULL) || (strlen(args) == 0)) {
		return (0);
	}
	if (key != NULL) {
		free(key);
	}
	key = malloc(KEYBUFSIZE);
	if (key == NULL) {
		perror("can't allocate memory");
		exit(1);
	}
	if (KEYBUFSIZE > strlen(args)) {
		len = strlen(args);
	}
	memset(key, 0x20, KEYBUFSIZE);
	memcpy(key, args, len);
	key[16] = 0x00;
	return (0);
}
