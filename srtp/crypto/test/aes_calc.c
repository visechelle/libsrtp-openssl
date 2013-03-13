/*
 * aes_calc.c
 *
 * A simple AES calculator for generating AES encryption values
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2005,2012, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*

   Example usage (with first NIST FIPS 197 test case):

   [sh]$ test/aes_calc 000102030405060708090a0b0c0d0e0f 00112233445566778899aabbccddeeff -v
   plaintext:      00112233445566778899aabbccddeeff
   key:            000102030405060708090a0b0c0d0e0f
   ciphertext:     69c4e0d86a7b0430d8cdb78070b4c55a

 */

#include <stdio.h>
#include <string.h>
#include "datatypes.h"
#include <openssl/aes.h>

void
usage (char *prog_name)
{
    printf("usage: %s <key> <plaintext> [-v]\n", prog_name);
    exit(255);
}

#define AES_KEY_LEN 16

int
main (int argc, char *argv[])
{
    v128_t data, key;
    AES_KEY exp_key;
    int len;
    int verbose = 0;

    if (argc == 3) {
        /* we're not in verbose mode */
        verbose = 0;
    } else if (argc == 4) {
        if (strncmp(argv[3], "-v", 2) == 0) {
            /* we're in verbose mode */
            verbose = 1;
        } else {
            /* unrecognized flag, complain and exit */
            usage(argv[0]);
        }
    } else {
        /* we've been fed the wrong number of arguments - compain and exit */
        usage(argv[0]);
    }

    /* read in key, checking length */
    if (strlen(argv[1]) > AES_KEY_LEN * 2) {
        fprintf(stderr,
                "error: too many digits in key "
                "(should be %d hexadecimal digits, found %u)\n",
                AES_KEY_LEN * 2, (unsigned)strlen(argv[1]));
        exit(1);
    }
    len = hex_string_to_octet_string((char*)&key, argv[1], AES_KEY_LEN * 2);
    /* check that hex string is the right length */
    if (len < AES_KEY_LEN * 2) {
        fprintf(stderr,
                "error: too few digits in key "
                "(should be %d hexadecimal digits, found %d)\n",
                AES_KEY_LEN * 2, len);
        exit(1);
    }

    /* read in plaintext, checking length */
    if (strlen(argv[2]) > 16 * 2) {
        fprintf(stderr,
                "error: too many digits in plaintext "
                "(should be %d hexadecimal digits, found %u)\n",
                16 * 2, (unsigned)strlen(argv[2]));
        exit(1);
    }
    len = hex_string_to_octet_string((char*)(&data), argv[2], 16 * 2);
    /* check that hex string is the right length */
    if (len < 16 * 2) {
        fprintf(stderr,
                "error: too few digits in plaintext "
                "(should be %d hexadecimal digits, found %d)\n",
                16 * 2, len);
        exit(1);
    }

    if (verbose) {
        /* print out plaintext */
        printf("plaintext:\t%s\n", octet_string_hex_string((uint8_t*)&data, 16));
    }

    /* encrypt plaintext */
    AES_set_encrypt_key((const unsigned char*)&key, 128, &exp_key);

    AES_encrypt((const unsigned char*)&data, (unsigned char*)&data, &exp_key);

    /* write ciphertext to output */
    if (verbose) {
        printf("key:\t\t%s\n", v128_hex_string(&key));
        printf("ciphertext:\t");
    }
    printf("%s\n", v128_hex_string(&data));

    return 0;
}

