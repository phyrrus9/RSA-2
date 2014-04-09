//
//  rsalib.h
//  RSA-2
//
//  Created by Ethan Laur on 4/8/14.
//  Copyright (c) 2014 Ethan Laur. All rights reserved.
//

#ifndef RSA_2_rsalib_h
#define RSA_2_rsalib_h

#include "bigint.h"
#include <sys/_types.h>

typedef __uint16_t rsa2_error;

#define RSA2_OUT_SIZE (0x08)

#define RSA2_NO_ERR   (0x0000)
#define RSA2_KEY_ERR  (0x0001)
#define RSA2_FILE_ERR (0x0002)

bigint rsa2_encrypt(bigint, bigint, bigint);
bigint rsa2_decrypt(bigint, bigint, bigint);
rsa2_error rsa2_encrypt_file(char *, char *, char *);
rsa2_error rsa2_decrypt_file(char *, char *, char *);
rsa2_error rsa2_write_keys(bigint, bigint, bigint, char *base = (char *)"rsa2");

#endif
