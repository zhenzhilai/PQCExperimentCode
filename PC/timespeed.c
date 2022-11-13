#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "kex.h"
#include "params.h"
#include "indcpa.h"
#include "polyvec.h"
#include "poly.h"
#include "cpucycles.h"
#include "speed_print.h"


#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ossl_typ.h>



#include <openssl/ec.h>
#include <openssl/ecdsa.h> 
#include <openssl/tls1.h>

#include "randombytes.h"
#include "time.h"

#define NTESTS 10
#define EXPAND 10000

uint64_t t[NTESTS];
uint8_t seed[KYBER_SYMBYTES] = {0};

uint64_t t_kp[NTESTS];
uint64_t t_enc[NTESTS];
uint64_t t_dec[NTESTS];
int pk_size[NTESTS];
int sk_size[NTESTS];
int ct_len[NTESTS];

static int cmp_uint64(const void *a, const void *b) {
  if(*(uint64_t *)a < *(uint64_t *)b) return -1;
  if(*(uint64_t *)a > *(uint64_t *)b) return 1;
  return 0;
}

static uint64_t median(uint64_t *l, size_t llen) {
  qsort(l,llen,sizeof(uint64_t),cmp_uint64);

  if(llen%2) return l[llen/2];
  else return (l[llen/2-1]+l[llen/2])/2;
}

static uint64_t average(uint64_t *pt, size_t tlen) {
  size_t i;
  uint64_t acc=0;

  for(i=0;i<tlen;i++)
    acc += pt[i];

  return acc/(tlen);
}


void process_t(uint64_t *pt, size_t tlen) {
  size_t i;
  static uint64_t overhead = -1;

  if(tlen < 2) {
    fprintf(stderr, "ERROR: Need a least two cycle counts!\n");
    return;
  }

  if(overhead  == (uint64_t)-1)
    overhead = cpucycles_overhead();

  tlen--;
  for(i=0;i<tlen;i++)
    pt[i] = pt[i+1] - pt[i] - overhead;

}

void print_t(const char *s, uint64_t *pt, size_t tlen) {
  
  printf("%s\n", s);
  printf("median: %llu cycles/ticks\n", (unsigned long long)median(pt, tlen-1));
  printf("average: %llu cycles/ticks\n", (unsigned long long)average(pt, tlen-1));
  printf("\n");

}

void write_t(const char *name, uint64_t *wt_kp, uint64_t *wt_enc, uint64_t *wt_dec, int *pksize, int * sksize, size_t tlen) {

  char fn[20];
  strcpy(fn, name);
  strcat(fn, "_time.csv");
  FILE *fp = fopen(fn, "w+");
    if (fp == NULL) {
        fprintf(stderr, "fopen() failed.\n");
        exit(EXIT_FAILURE);
    }

  
    fprintf(fp, "id,gen,enc,dec,pk,sk\n");


  for(size_t i=0;i<tlen;i++)
    fprintf(fp, "%lld,%llu,%llu,%llu,%d,%d\n", i, wt_kp[i], wt_enc[i], wt_dec[i], pksize[i], sksize[i]);

  
  fclose(fp);

}





void kyber_speed(){
  unsigned int i;
  unsigned int j;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key[CRYPTO_BYTES];

  clock_t st, ed;

  printf("start gen\n");

  for(i=0;i<NTESTS;i++) {
    st = clock();
    for(j=0;j<EXPAND;j++) {
      crypto_kem_keypair(pk, sk);
    }
    ed = clock();
    t_kp[i] = (uint64_t)(ed-st);
    pk_size[i] = CRYPTO_PUBLICKEYBYTES;
    sk_size[i] = CRYPTO_SECRETKEYBYTES;
  }
  // print_t(t_kp, NTESTS);
  // print_results("kyber_keypair: ", t, NTESTS);

  printf("start enc\n");

  for(i=0;i<NTESTS;i++) {
    st = clock();
    for(j=0;j<EXPAND;j++) {
      crypto_kem_enc(ct, key, pk);
    }
    ed = clock();
    t_enc[i] = (uint64_t)(ed-st);
  }
  // print_results("kyber_encaps: ", t_enc, NTESTS);

  printf("start dec\n");

  for(i=0;i<NTESTS;i++) {
    st = clock();
    for(j=0;j<EXPAND;j++) {
      crypto_kem_dec(key, ct, sk);
    }
    ed = clock();
    t_dec[i] = (uint64_t)(ed-st);
  }
  // print_results("kyber_decaps: ", t_dec, NTESTS);

  write_t("kyber", t_kp, t_enc, t_dec, pk_size, sk_size, NTESTS);

  printf("clocks per sec=%d\n",CLOCKS_PER_SEC);
  // print_t("kyber_keypair: ", t_kp, NTESTS);
  // print_t("kyber_encaps: ", t_enc, NTESTS);
  // print_t("kyber_decaps: ", t_dec, NTESTS);

}

void rsa_speed(){
    unsigned int i;
    unsigned int j;
    RSA				*r = NULL;
	  BIGNUM			*bne = NULL;
	  //int				bits = 7680;
    int				bits = 3072;
	  unsigned long	e = RSA_F4;

    uint8_t encin[32];

    char *sk = NULL;
    // sk = BN_bn2hex(RSA_get0_d(r));
    
    char *pk = NULL;
    // pk = BN_bn2hex(RSA_get0_e(r));

    bne = BN_new();
    BN_set_word(bne,e);

    r = RSA_new();

  clock_t st, ed;

  printf("start gen\n");

  // for(i=0;i<NTESTS;i++) {
  //   st = clock();
  //   printf("%d\n", i);
  //   for(j=0;j<EXPAND;j++) {
  //     if (j%100 == 0){
  //             printf("%d\n", j);
  //     }

  //       RSA_generate_key_ex(r, bits, bne, NULL);
  //       sk = BN_bn2hex(RSA_get0_d(r));
  //       pk = BN_bn2hex(RSA_get0_e(r));
  //       // printf("%s\n%s\n--------\n", sk, pk);
  //       pk_size[i] = strlen(pk);
  //       sk_size[i] = strlen(sk);
  //   }
  //   ed = clock();
  //   t_kp[i] = (uint64_t)(ed-st);
  //   pk_size[i] = CRYPTO_PUBLICKEYBYTES;
  //   sk_size[i] = CRYPTO_SECRETKEYBYTES;
  // }

  RSA_generate_key_ex(r, bits, bne, NULL);

  // print_t(t_kp, NTESTS);
  // print_results("kyber_keypair: ", t, NTESTS);


    // for(i=0;i<NTESTS;i++) {
    //     t_kp[i] = cpucycles();
    //     RSA_generate_key_ex(r, bits, bne, NULL);
    //     sk = BN_bn2hex(RSA_get0_d(r));
    //     pk = BN_bn2hex(RSA_get0_e(r));
    //     // printf("%s\n%s\n--------\n", sk, pk);
    //     pk_size[i] = strlen(pk);
    //     sk_size[i] = strlen(sk);
    // }
    // print_results("rsa_keypair: ", t_kp, NTESTS);

    int rsa_len = RSA_size(r);

    printf("rsa len: %d\n", rsa_len);

    char *encout = (char *)malloc(rsa_len + 1);
    char *decout = (char *)malloc(rsa_len + 1);

  printf("start enc\n");

  for(i=0;i<NTESTS;i++) {
    randombytes(encin, KYBER_SYMBYTES);
    st = clock();
    for(j=0;j<EXPAND;j++) {
      RSA_public_encrypt(rsa_len, encin, (unsigned char *)encout, r, RSA_NO_PADDING);
    }
    ed = clock();
    t_enc[i] = (uint64_t)(ed-st);

    st = clock();
    for(j=0;j<EXPAND;j++) {
      RSA_public_encrypt(rsa_len, encin, (unsigned char *)encout, r, RSA_NO_PADDING);
    }
    ed = clock();
    t_dec[i] = (uint64_t)(ed-st);


  }

    // for(i=0;i<NTESTS;i++) {
    //     t_enc[i] = cpucycles();
    //     randombytes(encin, KYBER_SYMBYTES);
    //     RSA_public_encrypt(rsa_len, encin, (unsigned char *)encout, r, RSA_NO_PADDING);
    //     // printf("%s\n--------\n", encout);
    //     // pk_size[i] = strlen(encout);
    // }
    // // print_results("rsa_enc: ", t_enc, NTESTS);

    // for(i=0;i<NTESTS;i++) {
    //     t_dec[i] = cpucycles();
    //     RSA_private_decrypt(rsa_len, (unsigned char *)encout, (unsigned char *)decout, r, RSA_NO_PADDING);
    // }
    // print_results("rsa_dec: ", t_dec, NTESTS);

    // process_t(t_kp, NTESTS);
    // process_t(t_enc, NTESTS);
    // process_t(t_dec, NTESTS);
  
    write_t("rsa", t_kp, t_enc, t_dec, pk_size, sk_size, NTESTS);

    printf("%d", CLOCKS_PER_SEC);

    // print_t("rsa_keypair: ", t_kp, NTESTS);
    // print_t("rsa_encaps: ", t_enc, NTESTS);
    // print_t("rsa_decaps: ", t_dec, NTESTS);

}

void ecdsa_speed(){
    unsigned int i;
    EC_KEY *eckey=EC_KEY_new();
    EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp192k1);
    EC_KEY_set_group(eckey,ecgroup);

    uint8_t encin[32];


    for(i=0;i<NTESTS;i++) {
        t_kp[i] = cpucycles();
        EC_KEY_generate_key(eckey);
        pk_size[i] = 32;
        sk_size[i] = 64;
    }
    // print_results("ecdsa_keypair: ", t_kp, NTESTS);


    ECDSA_SIG *signature;

    for(i=0;i<NTESTS;i++) {
        t_enc[i] = cpucycles();
        randombytes(encin, KYBER_SYMBYTES);
        signature = ECDSA_do_sign(encin, sizeof(encin), eckey);
    }
    // print_results("ecdsa_enc: ", t_enc, NTESTS);

    for(i=0;i<NTESTS;i++) {
        t_dec[i] = cpucycles();
        ECDSA_do_verify(encin, sizeof(encin), signature, eckey);
    }
    // print_results("ecdsa_dec: ", t_dec, NTESTS);



    process_t(t_kp, NTESTS);
    process_t(t_enc, NTESTS);
    process_t(t_dec, NTESTS);
  
    write_t("ecdsa", t_kp, t_enc, t_dec, pk_size, sk_size, NTESTS);

    print_t("ecdsa_keypair: ", t_kp, NTESTS);
    print_t("ecdsa_encaps: ", t_enc, NTESTS);
    print_t("ecdsa_decaps: ", t_dec, NTESTS);

}

int main()
{
  printf("%d\n", NTESTS);
  printf("%d\n", EXPAND);
  // kyber_speed();

  //////////////////////////////////////////////////////////////////////
  
	rsa_speed();

  //////////////////////////////////////////////////////////////////////

  // ecdsa_speed();

  return 0;
}
