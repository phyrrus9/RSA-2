//
//  main.cpp
//  RSA2-keygen
//
//  Created by Ethan Laur on 4/9/14.
//  Copyright (c) 2014 Ethan Laur. All rights reserved.
//

#include "rsalib.h"
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>

struct bigint_s { void *data; };

//macro functions
#define bs(a) (bigint_s {&p})

#define printcontents(a, b); \
printf(" %s=", b);\
buf = a.getdata();\
for (j = 0; j < RSA2_KEY_LEN; j++)\
printf("%02x", buf[j]);\
putchar(0x0a);\
free(buf);

#define totient(a, b) ((a - 1) * (b - 1))

bool bigint_isprime(bigint n) //really bad approach, but works
{
	bigint i;
	for (i = 1; i < n; i++)
		if ((n % i) == 0)
			return false;
	return true;
}

bigint bigint_modinverse(bigint n, bigint m)
{
	bigint x, an = n, am = m;
	an %= am;
	for (x = 1; x < am; x++)
		if ((an * x) % am == 1)
			return x;
	return 0;
}

bigint bigint_rand(unsigned int bits)
//generates a (bits * 8)-bit random number
{
	bigint a(bits, 0);
	unsigned char *buf = new unsigned char[bits];
	unsigned int i;
	for (i = 0; i < bits; i++) buf[i] = (rand() % 255);
	a.setrawdata(buf);
	return a;
}

void bigint_init(unsigned int width, unsigned int numargs, ...) //inits the entire list to n*8 bits
{
	va_list listptr;
	unsigned int i;
	va_start(listptr, numargs);
	for (i = 0; i < numargs; i++)
		((bigint *)(va_arg(listptr, bigint_s)).data)->resize(width); //yupp, this really does suck
	va_end(listptr);
}

bigint bigint_gcd(bigint ai, bigint bi)
{
	bigint a = ai;
	bigint b = bi;
	bigint c;
	while ( a != 0 )
	{
		c = a;
		a = b % a;
		b = c;
	}
	return b;
}

int main(int argc, char * * argv)
{
	bigint p, q, x, n, d, e, i;
	unsigned j;
	unsigned char *buf;
	bigint_init(RSA2_KEY_LEN, 7, bs(p), bs(q), bs(x), bs(n), bs(d), bs(e), bs(i));
	srand((unsigned int)time(NULL));
	//generate randoms for p, q
	do { p = bigint_rand(RSA2_KEY_LEN / 2); } while (!bigint_isprime(p));
	do { q = bigint_rand(RSA2_KEY_LEN / 2); } while (!bigint_isprime(q));
	printf("Using:\n");
	printcontents(p, "p");
	printcontents(q, "q");
	//compute n
	n = p * q;
	printcontents(n, "n");
	//compute φ(n)
	x = totient(p, q);
	printcontents(x, "x");
	//compute e
	do { e = bigint_rand(RSA2_KEY_LEN); }
	while (e <= 1 || !bigint_isprime(e) || e >= x);
	printcontents(e, "e");
	//compute d
	d = bigint_modinverse(e, n);
	printcontents(d, "d");
	printf("\n\n0x%02x\n", rsa2_write_keys(n, d, e, RSA2_KEY_LEN));
	return 0;
}

/*
 * right now, the write_keys is failing on ONLY the d exponent, no idea why,
 * but it never seems to be correct. This should be the only real bug in the
 * keygen program. If anybody wants to take a look at it, that would be cool
 * also, this only compiles with XCode at the moment, until I gen a Makefile
 */
