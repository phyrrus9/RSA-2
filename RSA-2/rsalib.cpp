//
//  rsalib.cpp
//  RSA-2
//
//  Created by Ethan Laur on 4/8/14.
//  Copyright (c) 2014 Ethan Laur. All rights reserved.
//

#include "rsalib.h"
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

bigint bigint_pow(bigint in, bigint pwr)
{
	bigint i, o = in;
	for (i = 0; i < pwr; i++)
		o *= in;
	return o;
}

bigint rsa2_encrypt(bigint in, bigint n, bigint k)
{
	bigint out;
	out = bigint_pow(in, n);
	out %= k;
	return out;
}

bigint rsa2_decrypt(bigint in, bigint n, bigint k)
{ return rsa2_encrypt(in, n, k); }

rsa2_error rsa2_read_keys(bigint *n, bigint *d, bigint *e, char *keyfile = (char *)"rsa2.pub")
{
	bigint *k = d ? d : e;
	FILE *infile;
	struct stat st;
	unsigned char *buf = NULL;
	if ((infile = fopen(keyfile, "rb")) == NULL)
		return RSA2_FILE_ERR;
	stat(keyfile, &st);
	buf = new unsigned char[st.st_size];
	k->resize((unsigned int)(st.st_size + 1)); //have just one extra byte
	fread(buf, st.st_size, 1, infile);
	fclose(infile);
	n->setrawdata(buf);
	k->setrawdata((buf + st.st_size / 2));
	return RSA2_NO_ERR;
}

rsa2_error rsa2_encrypt_file(char *keyfile, char *infile, char *outfile)
{
	bigint n, d; //we use d for encrypting, e for decrypting, sorta backwards
	struct stat st;
	unsigned int i;
	bigint tmp(RSA2_OUT_SIZE, 0);
	unsigned char tmpc, *obuf;
	FILE *in, *out;
	if (rsa2_read_keys(&n, &d, NULL, keyfile) != RSA2_NO_ERR)
		return RSA2_KEY_ERR;
	stat(infile, &st);
	if (!(st.st_mode & S_IFREG))
		return RSA2_FILE_ERR;
	if ((in = fopen(infile, "rb")) == NULL)
		return RSA2_FILE_ERR;
	if ((out = fopen(outfile, "wb")) == NULL)
		return RSA2_FILE_ERR;
	for (i = 0; i < st.st_size; i++)
	{
		fread(&tmpc, 1, 1, in);
		tmp = tmpc & 0xFF;
		tmp = rsa2_encrypt(tmp, n, d);
		tmp.resize(RSA2_OUT_SIZE);
		obuf = tmp.getdata();
		fwrite(obuf, RSA2_OUT_SIZE, 1, out);
		free(obuf);
	}
	fclose(in);
	fclose(out);
	return RSA2_NO_ERR;
}

rsa2_error rsa2_write_keys(bigint n, bigint d, bigint e, unsigned int bits, char *base)
{
	char pubkeyfile[1024], privkeyfile[1024];
	unsigned char *obuf;
	FILE *pubkey, *privkey;
	sprintf(pubkeyfile, "%s.pub", base);
	sprintf(privkeyfile, "%s.pri", base);
	if ((pubkey = fopen(pubkeyfile, "wb")) == NULL)
		return RSA2_FILE_ERR;
	if ((privkey = fopen(privkeyfile, "wb")) == NULL)
	{
		n.resize(bits);
		d.resize(bits);
		e.resize(bits);
		obuf = n.getdata();
		fwrite(obuf, bits, 1, pubkey);
		fwrite(obuf, bits, 1, privkey);
		free(obuf);
		obuf = e.getdata();
		fwrite(obuf, bits, 1, pubkey);
		free(obuf);
		obuf = d.getdata();
		fwrite(obuf, bits, 1, privkey);
		free(obuf);
		fclose(pubkey);
		fclose(privkey);
		return RSA2_NO_ERR;
	}
	fclose(pubkey);
	return RSA2_FILE_ERR;
}

rsa2_error rsa2_decrypt_file(char *keyfile, char *infile, char *outfile)
{ return rsa2_encrypt_file(keyfile, infile, outfile); }

int main(){} //temporary
