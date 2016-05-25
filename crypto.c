/*

Copyright (C) 2016 John Ventura

This file is part of Net Needle.

NetNeedle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

NetNeedle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with Net Needle. If not, see http://www.gnu.org/licenses/.

*/

#include <fcntl.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sodium.h>
#include <sodium/randombytes.h>

// encrypt() and decrypt() are wrappers for libsodium
// getrandom8() and getrandom32() generate random numbers

uint8_t getrandom8() {
	int fd;
	uint8_t rval;
	fd = open("/dev/urandom", O_RDONLY);
	if(read(fd, &(rval), 1) == 0) {
		rval = 0xb7;  // if we can't read from /dev/urandom default to this
	}
	close(fd);
	return(rval);
}

uint32_t getrandom32() {
	int fd;
	uint32_t rval;
	fd = open("/dev/urandom", O_RDONLY);
	if(read(fd, &(rval), 4) == 0) {
		rval = 0xb7;  // if we can't read from /dev/urandom default to this
	}
	close(fd);
	return(rval);
}


int encrypt(uint8_t *plaintext, int plaintext_len, uint8_t *pk, uint8_t *sk, uint8_t *nonce, uint8_t *ciphertext) {
        int rval = 0;
        uint8_t *plaintext_temp;

        plaintext_temp = (uint8_t *)malloc(plaintext_len +  crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES);
        if(plaintext_temp == NULL) {
                perror("can't allocate memory");
                exit(1);
        }
        memset(plaintext_temp, 0x00, plaintext_len);

        memcpy(plaintext_temp + crypto_box_ZEROBYTES, plaintext, plaintext_len);

        if(crypto_box(ciphertext, plaintext_temp, crypto_box_ZEROBYTES + plaintext_len, nonce, pk, sk) == 0) {
                // get rid of the nulls
		memcpy(plaintext_temp, ciphertext + crypto_box_BOXZEROBYTES, crypto_box_BOXZEROBYTES + plaintext_len);
		memcpy(ciphertext, plaintext_temp, crypto_box_BOXZEROBYTES + plaintext_len);
                //memcpy(ciphertext, ciphertext + crypto_box_ZEROBYTES, crypto_box_BOXZEROBYTES + plaintext_len);
                //return the size of what we just encrypted
                rval = crypto_box_BOXZEROBYTES + plaintext_len;
        }
                free(plaintext_temp);
                return (rval);
}

int decrypt(uint8_t *ciphertext, int ciphertext_len, uint8_t *pk, uint8_t *sk, uint8_t *nonce, uint8_t *plaintext) {
        uint8_t *cipher_temp;
        int rval = 0;

        cipher_temp = (uint8_t *)malloc(ciphertext_len + crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES);
        if(cipher_temp == NULL) {
                perror("can't allocate memory");
                exit(1);
        }

        // put the prefix null bytes in place
        memset(cipher_temp, 0x00, crypto_box_BOXZEROBYTES + ciphertext_len);
        memcpy(cipher_temp + crypto_box_BOXZEROBYTES, ciphertext, crypto_box_ZEROBYTES + ciphertext_len);
        if(crypto_box_open(plaintext, cipher_temp, crypto_box_BOXZEROBYTES + ciphertext_len, nonce, pk, sk) == 0) {
                // if we don't decrypt or if signature doesn't validate, return 0
                memcpy(cipher_temp, plaintext + crypto_box_ZEROBYTES, ciphertext_len);
		memcpy(plaintext, cipher_temp, ciphertext_len);
                rval = ciphertext_len;
        }
        free(cipher_temp);
        return(rval);
}

