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

#define NTESTS 10000

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
	BIO				*bp_public = NULL, *bp_private = NULL;

	int				bits = 2048;
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

	// 2. save public key
	bp_public = BIO_new_file("public.pem", "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	if(ret != 1){
		goto free_all;
	}

	// 3. save private key
	bp_private = BIO_new_file("private.pem", "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

	// 4. free
free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);

  // printf("sasaa");
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







  unsigned int i,j;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  //uint8_t key_a[1024*1024];
  //uint8_t key_b[1024*1024];
  uint8_t key_a[CRYPTO_BYTES];
  uint8_t key_b[CRYPTO_BYTES];


    
    clock_t start,end;
    start = clock();


  for(i=0;i<NTESTS;i++) {
    // Key-pair generation
    crypto_kem_keypair(pk, sk);
      
    /*
    printf("Public Key: ");
    for(j=0;j<CRYPTO_PUBLICKEYBYTES;j++)
      printf("%02x",pk[j]);
    printf("\n");
    printf("Secret Key: ");
    for(j=0;j<CRYPTO_SECRETKEYBYTES;j++)
      printf("%02x",sk[j]);
    printf("\n");
     */

    // Encapsulation
      
    crypto_kem_enc(ct, key_b, pk);
      /*
    printf("Ciphertext: ");
    for(j=0;j<CRYPTO_CIPHERTEXTBYTES;j++)
      printf("%02x",ct[j]);
    printf("\n");
    printf("Shared Secret B: ");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_b[j]);
    printf("\n");
       */

    // Decapsulation
       
    crypto_kem_dec(key_a, ct, sk);
      /*
    printf("Shared Secret A: ");
    for(j=0;j<CRYPTO_BYTES;j++)
      printf("%02x",key_a[j]);
    printf("\n");

    for(j=0;j<CRYPTO_BYTES;j++) {
      if(key_a[j] != key_b[j]) {
        fprintf(stderr, "ERROR\n");
        return -1;
      }
    }
     */
  }

    end = clock();
    printf("clocks per sec=%d\n",CLOCKS_PER_SEC);
    printf("full steps time=%f ms for %d rounds\n",(((double)end-start)/CLOCKS_PER_SEC) * 1000, NTESTS);
    
    // // // // // // // //
    
    
    uint8_t pk2[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk2[CRYPTO_SECRETKEYBYTES];
    
    
    clock_t start2,end2;
    start2 = clock();


  for(i=0;i<NTESTS;i++) {
      // Key-pair generation
      crypto_kem_keypair(pk2, sk2);
    
  }
      
      end2 = clock();
      printf("key generation time=%f ms for %d rounds\n",(((double)end2-start2)/CLOCKS_PER_SEC) * 1000, NTESTS);
    
    // // // // // // // //
    
    uint8_t pk3[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk3[CRYPTO_SECRETKEYBYTES];
    uint8_t ct3[CRYPTO_CIPHERTEXTBYTES];
    //uint8_t key_a[1024*1024];
    //uint8_t key_b[1024*1024];
    uint8_t key_b3[CRYPTO_BYTES];
    
    
    // Key-pair generation
    crypto_kem_keypair(pk3, sk3);
    
    clock_t start3,end3;
    start3 = clock();


  for(i=0;i<NTESTS;i++) {
      crypto_kem_enc(ct3, key_b3, pk3);
    
  }
      
      end3 = clock();
      printf("encryption time=%f ms for %d rounds\n",(((double)end3-start3)/CLOCKS_PER_SEC) * 1000, NTESTS);

    // // // // // // // //

    uint8_t pk4[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk4[CRYPTO_SECRETKEYBYTES];
    uint8_t ct4[CRYPTO_CIPHERTEXTBYTES];
    //uint8_t key_a[1024*1024];
    //uint8_t key_b[1024*1024];
    uint8_t key_a4[CRYPTO_BYTES];
    uint8_t key_b4[CRYPTO_BYTES];
    
    // Key-pair generation
    crypto_kem_keypair(pk4, sk4);
    
    crypto_kem_enc(ct4, key_b4, pk4);
    
    
    clock_t start4,end4;
    start4 = clock();



  for(i=0;i<NTESTS;i++) {
      crypto_kem_dec(key_a4, ct4, sk4);
    
  }
      
      end4 = clock();
      printf("decryption time=%f ms for %d rounds\n",(((double)end4-start4)/CLOCKS_PER_SEC) * 1000, NTESTS);
    
    
    
    
    
    // printf("-----------------A simple example--------\n");
    
    // printf("Public Key: ");
    // for(j=0;j<CRYPTO_PUBLICKEYBYTES;j++)
    //   printf("%02x",pk[j]);
    // printf("\n");
    // printf("Secret Key: ");
    // for(j=0;j<CRYPTO_SECRETKEYBYTES;j++)
    //   printf("%02x",sk[j]);
    // printf("\n");
     

    // // Encapsulation
      
    // printf("Ciphertext: ");
    // for(j=0;j<CRYPTO_CIPHERTEXTBYTES;j++)
    //   printf("%02x",ct[j]);
    // printf("\n");
    // printf("Shared Secret B: ");
    // for(j=0;j<CRYPTO_BYTES;j++)
    //   printf("%02x",key_b[j]);
    // printf("\n");

    // // Decapsulation

    // printf("Shared Secret A: ");
    // for(j=0;j<CRYPTO_BYTES;j++)
    //   printf("%02x",key_a[j]);
    // printf("\n");

    // for(j=0;j<CRYPTO_BYTES;j++) {
    //   if(key_a[j] != key_b[j]) {
    //     fprintf(stderr, "ERROR\n");
    //     return -1;
    //   }
    // }
    
  return 0;
}
