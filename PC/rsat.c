/* Deterministic randombytes by Daniel J. Bernstein */
/* taken from SUPERCOP (https://bench.cr.yp.to)     */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "kem.h"
#include "randombytes.h"

#include <time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>
#include <string.h>

#define NTESTS 100

static uint32_t seed[32] = {
  3,1,4,1,5,9,2,6,5,3,5,8,9,7,9,3,2,3,8,4,6,2,6,4,3,3,8,3,2,7,9,5
};
static uint32_t in[12];
static uint32_t out[8];
static int outleft = 0;

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

static void surf(void)
{
  uint32_t t[12]; uint32_t x; uint32_t sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
  for (i = 0;i < 8;++i) out[i] = seed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

void randombytes(uint8_t *x,size_t xlen)
{
  while (xlen > 0) {
    if (!outleft) {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
    *x = out[--outleft];
    //printf("%02x", *x);/////////////////
    ++x;
    --xlen;
  }
  //printf("\n");/////////////
}



// #define KEY_LENGTH  4096
// #define PUB_EXP     3
// #define PRINT_KEYS
// #define WRITE_TO_FILE


int main(void)
{
  	int				ret = 0;
	RSA				*r = NULL;
	BIGNUM			*bne = NULL;
	// BIO				*bp_public = NULL, *bp_private = NULL;

	//int				bits = 7680;
    int				bits = 1024;
	unsigned long	e = RSA_F4;

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne,e);
	if(ret != 1){
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if(ret != 1){
		goto free_all;
	}
///////////////////////////////////////

    // char *sk = NULL;
    // sk = BN_bn2hex(RSA_get0_d(r));
    // printf("%s\n", sk);

    // char *pk = NULL;
    // pk = BN_bn2hex(RSA_get0_e(r));
    // printf("%s\n", pk);

    // int scbits =  RSA_security_bits(r);
    // printf("Security bits: %d\n", scbits);


    // RSA_public_encrypt(int flen, const unsigned char *from,
    //                    unsigned char *to, RSA *rsa, int padding);
    int rsa_len = RSA_size(r);
    char *encin = "ab";
    char *encout = (char *)malloc(rsa_len + 1);
    

    // unsigned char *u_encin = (unsigned char *)&encin;
    // unsigned char *u_encout = (unsigned char *)&encout;

    int enc;

      // printf("check point\n");

      // printf("%d\n", RSA_size(r));
    
    enc = RSA_public_encrypt(rsa_len, (unsigned char *)encin, (unsigned char *)encout, r, RSA_NO_PADDING);

    // printf("%d\n", enc);
    // printf("%s\n", (char *)encin);
    // printf("%s\n", (char *)encout);
    

    // int RSA_private_decrypt(int flen, const unsigned char *from,
    //                     unsigned char *to, RSA *rsa, int padding);

    
    char *decout = (char *)malloc(rsa_len + 1);
    
    int dec;

      // printf("check point\n");

    dec = RSA_private_decrypt(rsa_len, (unsigned char *)encout, (unsigned char *)decout, r, RSA_NO_PADDING);

    // printf("%d\n", dec);
    // printf("%s\n", (char *)decout);




// ///////////////////////////////////////
// 	// 2. save public key
// 	bp_public = BIO_new_file("public.pem", "w+");
// 	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
// 	if(ret != 1){
// 		goto free_all;
// 	}

// 	// 3. save private key
// 	bp_private = BIO_new_file("private.pem", "w+");
// 	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

// ///////////////////////////////////////
//   printf("check point\n");
///////////////////////////////////////

//  clock_t start,end;
//     start = clock();


//   for(int i=0;i<NTESTS;i++) {
//     ret = RSA_generate_key_ex(r, bits, bne, NULL);
//   }
//     end = clock();

//         printf("clocks per sec=%d\n",CLOCKS_PER_SEC);
//     printf("rsa generate time=%f ms for %d rounds\n",(((double)end-start)/CLOCKS_PER_SEC) * 1000, NTESTS);






    	// 4. free
free_all:

	// BIO_free_all(bp_public);
	// BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);

  // RSA *test;
  // test = RSA_new();
  // printf("sasaa");
  // int d = RSA_bits(test);
  // printf("%d", d);

//   size_t pri_len;            // Length of private key
//   size_t pub_len;            // Length of public key
//   char   *pri_key;           // Private key
//   char   *pub_key;           // Public key
//   char   msg[KEY_LENGTH/8];  // Message to encrypt
//   char   *encrypt = NULL;    // Encrypted message
//   char   *decrypt = NULL;    // Decrypted message
//   char   *err;               // Buffer for any error messages

//   // Generate key pair
//   printf("Generating RSA (%d bits) keypair...", KEY_LENGTH);
//   fflush(stdout);
//   RSA *keypair = RSA_generate_key(KEY_LENGTH, PUB_EXP, NULL, NULL);

// // To get the C-string PEM form:
//     BIO *pri = BIO_new(BIO_s_mem());
//     BIO *pub = BIO_new(BIO_s_mem());

//     PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
//     PEM_write_bio_RSAPublicKey(pub, keypair);

//     pri_len = BIO_pending(pri);
//     pub_len = BIO_pending(pub);

//     pri_key = malloc(pri_len + 1);
//     pub_key = malloc(pub_len + 1);

//     BIO_read(pri, pri_key, pri_len);
//     BIO_read(pub, pub_key, pub_len);

//     pri_key[pri_len] = '\0';
//     pub_key[pub_len] = '\0';

//     #ifdef PRINT_KEYS
//         printf("\n%s\n%s\n", pri_key, pub_key);
//     #endif
//     printf("done.\n");

    
  return 0;
}
