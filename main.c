#include <gmp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <conio.h>
#include "gost3411-2012-core.h"

GOST34112012Context CTX;

int main () {
	printf("Welcome to program realization of Lamport digital signature scheme\n");
	printf("\n");
	gmp_randstate_t rs; 
	gmp_randinit_mt (rs), gmp_randseed_ui (rs, time (0)); 
	mpz_t m[256][2], M[256][2], s[256], check1[256], check2[256], r[256], n, h, v; 
	int row, col, i, bit_index, b;
	printf("Generating secret key (256 pairs of 256-bit numbers):\n");
  
	for (row = 0; row < 256; row++) {
		for (col = 0; col < 2; col++) {
			mpz_inits (m[row][col], n, 0);	
			mpz_urandomb (n, rs, 256); // Secret key generation (256 pairs of prime numbers, 256 bits)
			mpz_set (m[row][col], n); // Write to array
	  	}
	}
  	
	for (row = 0; row < 256; row++) {
		gmp_printf ("%Zx %Zx\n", m[row][0], m[row][1]); // Secret key printing
	}

	printf("\n");

	printf("Generating public key (256-bit hash-functions of 256 pairs of prime numbers):\n");
	unsigned char H [32];
	char str [65];
	unsigned char C[64];

	for (row = 0; row < 256; row++) {
	  	for (col = 0; col < 2; col++) {	
		  	GOST34112012Init (&CTX, 256);
		  	mpz_inits (h, M[row][col], 0);	
		  	mpz_get_str (C, 16, m[row][col]); 
		    GOST34112012Update (&CTX, C, strlen(C)); // Hashing each number from a secret key into hashes with a size of 256 bits
		    GOST34112012Final (&CTX, H);
		    for (i=0; i < 32; i++) sprintf (str+(2*i), "%02X", H[i]);
		    mpz_set_str (h, str, 16);
		    mpz_set (M[row][col], h); // Write to an array which will be the public key
		}
	}
	
    for (row = 0; row < 256; row++) gmp_printf ("%ZX %ZX\n", M[row][0], M[row][1]); // Public key printing

	printf("\n");
	printf("Generating hash-function to our message:\n");
	mpz_init (v);
	unsigned char buf [512];
	int l;
	FILE *fp = fopen ("text.txt", "rb");
	GOST34112012Init (&CTX, 256);
	
  	do {
    	l = fread (buf, 1, 512, fp),
    	GOST34112012Update (&CTX, buf, l);
    } while (! feof (fp));
  	
	GOST34112012Final(&CTX, H); // Generating a hash function to a file with a message
	
	for (i=0; i < 32; i++) sprintf (str+(2*i), "%02X", H[i]);  
	
	printf ("Hash value is H = %s\n", str);
	mpz_set_str (v, str, 16);
	gmp_printf ("%s = %ZX\n", "v", v);
  
	printf("\n");
	printf("Checking each of 256 bits...\n");
	
	for (bit_index = 0; bit_index < 256; bit_index++) { 		
		if (mpz_tstbit (v, bit_index) != 0) // checking each bit of the hash function 
			*s[bit_index] = *m[bit_index][1]; // if bit in position equals 1, write to signature array value from the second column of the secrete key
			*s[bit_index] = *m[bit_index][0]; //if bit in position equals 0, write to signature array value from the first column of the secrete key 
	}
	
	printf("\n");
	printf("Generating signature to message:\n");
	for (row = 0; row < 256; row++) gmp_printf ("%Zx\n", s[row]); // Printing of resulted signature
 
	printf("\n");
	printf("Hashing the message and checking each of 256 bits...\n");
	
	for (bit_index = 0; bit_index < 256; bit_index++) { // Verifying each bit of hash value of the singature
		if (mpz_tstbit (v, bit_index) != 0)
			*check1[bit_index] = *M[bit_index][1]; // if bit in position equals 1 write to "check1" array value from the second column of public key
			*check1[bit_index] = *M[bit_index][0]; // if bit in position equals 0 write to "check1" array value from the first column of public key
	}
	
	printf("\n");
	printf("Construct set of hashs according to checked bits:\n");
	
	for (row = 0; row < 256; row++) gmp_printf ("%ZX\n", check1[row]); // Printing of the first verifying array

	printf("\n");
	printf("Hashing of signature...\n");
	
	for (row = 0; row < 256; row++) {
  		for (col = 0; col < 2; col++) {	
		  	GOST34112012Init (&CTX, 256);
		  	mpz_inits (h, check2[row], 0);	
		  	mpz_get_str (C, 16, s[row]); 
		    GOST34112012Update (&CTX, C, strlen(C)); 
		    GOST34112012Final (&CTX, H); // Calculating hash values of the signature array
		    for (i=0; i < 32; i++) sprintf (str+(2*i), "%02X", H[i]);
		    mpz_set_str (h, str, 16);
		    mpz_set (check2[row], h); // Writing to the second verifying array
	  	}
  	}
  
	printf("\n");  
	printf("Construct set of hashs according to hashed signature:\n");
	
	for (row = 0; row < 256; row++) gmp_printf ("%ZX\n", check2[row]); // Printing of the second verifying array

	printf("\n");
	printf("Compare of two sets of hashes...\n");
	
	for (row=0; row < 256; row++) {
		b = mpz_cmp (check1[row], check2[row]); // Compare each element of the verifying arrays from one string with another
		if (b!=0) { // If the value does not match, output the message and end the program
			printf("Hashs are not equal! The message is wrong!\n");
			getch();
			return 0;	
		}
	}

	printf("\n");
	printf("Hashs are equal! The message is correct!\n"); // If the verification is successful, we display a message about the successful verification
	getch();
	
	return 0;
}
