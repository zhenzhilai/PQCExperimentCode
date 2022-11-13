#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "kem.h"
#include "kex.h"
#include "params.h"
 
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
#include "symmetric.h"

#define NTESTS 10002

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

static void pack_pk(uint8_t r[KYBER_INDCPA_PUBLICKEYBYTES],
                    polyvec *pk,
                    const uint8_t seed[KYBER_SYMBYTES])
{
  size_t i;
  polyvec_tobytes(r, pk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    r[i+KYBER_POLYVECBYTES] = seed[i];
}

static void unpack_pk(polyvec *pk,
                      uint8_t seed[KYBER_SYMBYTES],
                      const uint8_t packedpk[KYBER_INDCPA_PUBLICKEYBYTES])
{
  size_t i;
  polyvec_frombytes(pk, packedpk);
  for(i=0;i<KYBER_SYMBYTES;i++)
    seed[i] = packedpk[i+KYBER_POLYVECBYTES];
}

static void pack_sk(uint8_t r[KYBER_INDCPA_SECRETKEYBYTES], polyvec *sk)
{
  polyvec_tobytes(r, sk);
}

static void unpack_sk(polyvec *sk, const uint8_t packedsk[KYBER_INDCPA_SECRETKEYBYTES])
{
  polyvec_frombytes(sk, packedsk);
}

#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)




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
  strcat(fn, ".csv");
  FILE *fp = fopen(fn, "w+");
    if (fp == NULL) {
        fprintf(stderr, "fopen() failed.\n");
        exit(EXIT_FAILURE);
    }

  
    fprintf(fp, "id,gen,enc,dec,pk,sk\n");


  for(size_t i=1;i<tlen-1;i++)
    fprintf(fp, "%lld,%llu,%llu,%llu,%d,%d\n", i, wt_kp[i], wt_enc[i], wt_dec[i], pksize[i], sksize[i]);

  
  fclose(fp);

}





void kyber_speed(){
  unsigned int i;
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];
  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t key[CRYPTO_BYTES];

  for(i=0;i<NTESTS;i++) {
    t_kp[i] = cpucycles();
    crypto_kem_keypair(pk, sk);
    pk_size[i] = CRYPTO_PUBLICKEYBYTES;
    sk_size[i] = CRYPTO_SECRETKEYBYTES;
  }
  // print_t(t_kp, NTESTS);
  // print_results("kyber_keypair: ", t, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t_enc[i] = cpucycles();
    crypto_kem_enc(ct, key, pk);
  }
  // print_results("kyber_encaps: ", t_enc, NTESTS);

  for(i=0;i<NTESTS;i++) {
    t_dec[i] = cpucycles();
    crypto_kem_dec(key, ct, sk);
  }
  // print_results("kyber_decaps: ", t_dec, NTESTS);

  process_t(t_kp, NTESTS);
  process_t(t_enc, NTESTS);
  process_t(t_dec, NTESTS);

  write_t("kyber", t_kp, t_enc, t_dec, pk_size, sk_size, NTESTS);

  print_t("kyber_keypair: ", t_kp, NTESTS);
  print_t("kyber_encaps: ", t_enc, NTESTS);
  print_t("kyber_decaps: ", t_dec, NTESTS);

}

void rsa_speed(){
    unsigned int i;
    RSA				*r = NULL;
	  BIGNUM			*bne = NULL;
	  //int				bits = 7680;
    int				bits = 3072;
	  unsigned long	e = RSA_F4;

    uint8_t encin[32];

    char *sk = NULL;
    // sk = BN_bn2hex(RSA_get0_d(r));
    
    char *pk = NULL;

    char *n = NULL;
    char *p = NULL;
    char *q = NULL;
    // pk = BN_bn2hex(RSA_get0_e(r));

    bne = BN_new();
    BN_set_word(bne,e);

    r = RSA_new();


    for(i=0;i<NTESTS;i++) {
        t_kp[i] = cpucycles();
        RSA_generate_key_ex(r, bits, bne, NULL);
        sk = BN_bn2hex(RSA_get0_d(r));
        pk = BN_bn2hex(RSA_get0_e(r));
        // printf("%s\n%s\n--------\n", sk, pk);
        pk_size[i] = strlen(pk);
        sk_size[i] = strlen(sk);
    }

    n = BN_bn2hex(RSA_get0_n(r));
    p = BN_bn2hex(RSA_get0_p(r));
    q = BN_bn2hex(RSA_get0_q(r));
    // printf("%s\n%s\n%s\n%s\n%s\n--------\n", n, sk, pk, p, q);
    // print_results("rsa_keypair: ", t_kp, NTESTS);

    // int rsa_len = RSA_size(r);

    // printf("rsa len: %d\n", rsa_len);

    // char *encout = (char *)malloc(rsa_len + 1);
    // char *decout = (char *)malloc(rsa_len + 1);

    // // randombytes(encin, KYBER_SYMBYTES);

    // for(i=0;i<NTESTS;i++) {
    //     t_enc[i] = cpucycles();
    //     randombytes(encin, KYBER_SYMBYTES);
    //     RSA_public_encrypt(rsa_len, encin, (unsigned char *)encout, r, RSA_PKCS1_PSS_PADDING);
    //     // printf("%s\n--------\n", encout);
    //     // pk_size[i] = strlen(encout);
    // }
    // // print_results("rsa_enc: ", t_enc, NTESTS);

    // for(i=0;i<NTESTS;i++) {
    //     t_dec[i] = cpucycles();
    //     RSA_private_decrypt(rsa_len, (unsigned char *)encout, (unsigned char *)decout, r, RSA_PKCS1_PSS_PADDING);
    // }
    // // print_results("rsa_dec: ", t_dec, NTESTS);

    process_t(t_kp, NTESTS);
    process_t(t_enc, NTESTS);
    process_t(t_dec, NTESTS);
  
    write_t("rsa", t_kp, t_enc, t_dec, pk_size, sk_size, NTESTS);

    print_t("rsa_keypair: ", t_kp, NTESTS);
    print_t("rsa_encaps: ", t_enc, NTESTS);
    print_t("rsa_decaps: ", t_dec, NTESTS);

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

void kyber_kex(){
  uint8_t pkb[CRYPTO_PUBLICKEYBYTES];
  uint8_t skb[CRYPTO_SECRETKEYBYTES];

  uint8_t pka[CRYPTO_PUBLICKEYBYTES];
  uint8_t ska[CRYPTO_SECRETKEYBYTES];

  uint8_t eska[CRYPTO_SECRETKEYBYTES];

  uint8_t uake_senda[KEX_UAKE_SENDABYTES];
  uint8_t uake_sendb[KEX_UAKE_SENDBBYTES];

  uint8_t ake_senda[KEX_AKE_SENDABYTES];
  uint8_t ake_sendb[KEX_AKE_SENDBBYTES];

  uint8_t tk[KEX_SSBYTES];
  uint8_t ka[KEX_SSBYTES];
  uint8_t kb[KEX_SSBYTES];
  uint8_t zero[KEX_SSBYTES];
  int i;

  for(i=0;i<KEX_SSBYTES;i++)
    zero[i] = 0;
    
    crypto_kem_keypair(pkb, skb); // Generate static key for Bob

    crypto_kem_keypair(pka, ska); // Generate static key for Alice
    
    
    clock_t start,end;
    start = clock();


  for(i=0;i<NTESTS-2;i++) {

  // Perform unilaterally authenticated key exchange

  kex_uake_initA(uake_senda, tk, eska, pkb); // Run by Alice

  kex_uake_sharedB(uake_sendb, kb, uake_senda, skb); // Run by Bob

  kex_uake_sharedA(ka, uake_sendb, tk, eska); // Run by Alice

  //if(memcmp(ka,kb,KEX_SSBYTES))
  //  printf("Error in UAKE\n");

  //if(!memcmp(ka,zero,KEX_SSBYTES))
  //  printf("Error: UAKE produces zero key\n");
    
  }
    
    end = clock();
    printf("clocks per sec=%lu\n",CLOCKS_PER_SEC);
    printf("unilaterally authenticated kex time=%f ms for %d rounds\n",(((double)end-start)/CLOCKS_PER_SEC) * 1000, NTESTS-2);

    printf("KEX_UAKE_SENDABYTES: %d\n",KEX_UAKE_SENDABYTES);
    printf("KEX_UAKE_SENDBBYTES: %d\n",KEX_UAKE_SENDBBYTES);
}

void rsa_kex(){
 unsigned int i;
    RSA				*r = NULL;
	  BIGNUM			*bne = NULL;
	  //int				bits = 7680;
    int				bits = 3072;
	  unsigned long	e = RSA_F4;

    uint8_t encin[32];
    uint8_t encout[32];
    uint8_t decout[32];

    char *sk = NULL;
    // sk = BN_bn2hex(RSA_get0_d(r));
    
    char *pk = NULL;

    char *n = NULL;
    char *p = NULL;
    char *q = NULL;
    // pk = BN_bn2hex(RSA_get0_e(r));


  uint8_t buf[2*KYBER_SYMBYTES];
  /* Will contain key, coins */
  uint8_t kr[2*KYBER_SYMBYTES];
  uint8_t ss[KYBER_SYMBYTES];



    bne = BN_new();
    BN_set_word(bne,e);

    r = RSA_new();


    RSA_generate_key_ex(r, bits, bne, NULL);
    int rsa_len = RSA_size(r);
    

    clock_t start,end;
    start = clock();

    for(i=0;i<NTESTS-2;i++) {
      // A
        RSA_generate_key_ex(r, bits, bne, NULL);
        randombytes(encin, KYBER_SYMBYTES);
        RSA_public_encrypt(rsa_len, encin, (unsigned char *)encout, r, RSA_PKCS1_PSS_PADDING);
        kdf(ss, kr, 2*KYBER_SYMBYTES);

      // B
        RSA_private_decrypt(rsa_len, (unsigned char *)encout, (unsigned char *)decout, r, RSA_PKCS1_PSS_PADDING);
        kdf(ss, kr, 2*KYBER_SYMBYTES);
        randombytes(encin, KYBER_SYMBYTES);
        RSA_public_encrypt(rsa_len, encin, (unsigned char *)encout, r, RSA_PKCS1_PSS_PADDING);
        kdf(ss, kr, 2*KYBER_SYMBYTES);
        
      // A
        RSA_private_decrypt(rsa_len, (unsigned char *)encout, (unsigned char *)decout, r, RSA_PKCS1_PSS_PADDING);
        kdf(ss, kr, 2*KYBER_SYMBYTES);

      // kdf(ss, kr, 2*KYBER_SYMBYTES);
    }

    end = clock();

    printf("clocks per sec=%lu\n",CLOCKS_PER_SEC);
    printf("unilaterally authenticated kex time=%f ms for %d rounds\n",(((double)end-start)/CLOCKS_PER_SEC) * 1000, NTESTS-2);


}

// void special_test(){
//   unsigned int i;
//   uint8_t pk[CRYPTO_PUBLICKEYBYTES];
//   uint8_t sk[CRYPTO_SECRETKEYBYTES];
//   uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
//   uint8_t key[CRYPTO_BYTES];

//   // for(i=0;i<NTESTS;i++) {
//   //   t_kp[i] = cpucycles();
//   //   crypto_kem_keypair(pk, sk);
//   //   pk_size[i] = CRYPTO_PUBLICKEYBYTES;
//   //   sk_size[i] = CRYPTO_SECRETKEYBYTES;
//   // }
//   // // print_t(t_kp, NTESTS);
//   // // print_results("kyber_keypair: ", t, NTESTS);

//   // for(i=0;i<NTESTS;i++) {
//   //   t_enc[i] = cpucycles();
//   //   crypto_kem_enc(ct, key, pk);
//   // }
//   // // print_results("kyber_encaps: ", t_enc, NTESTS);

//   // for(i=0;i<NTESTS;i++) {
//   //   t_dec[i] = cpucycles();
//   //   crypto_kem_dec(key, ct, sk);
//   // }
//   // // print_results("kyber_decaps: ", t_dec, NTESTS);

//   crypto_kem_keypair(pk, sk);
//   // crypto_kem_enc(ct, key, pk);
//   // crypto_kem_dec(key, ct, sk);


//   uint8_t seed[KYBER_SYMBYTES];
//   polyvec pkpv, at[KYBER_K];

//   for(i=0;i<NTESTS;i++) {
//     t_kp[i] = cpucycles();
//     hash_h(ct, sk, CRYPTO_SECRETKEYBYTES);
//   }

//   for(i=0;i<NTESTS;i++) {
//     t_enc[i] = cpucycles();
//     unpack_pk(&pkpv, seed, pk);
//     gen_at(at, seed);
//   }

//   // unpack_pk(&pkpv, seed, pk);
//   // gen_at(at, seed);

//   polyvec skpv;

//   // unpack_sk(&skpv, sk);

//   for(i=0;i<NTESTS;i++) {
//     t_dec[i] = cpucycles();
//     unpack_sk(&skpv, sk);
//   }


//   process_t(t_kp, NTESTS);
//   process_t(t_enc, NTESTS);
//   process_t(t_dec, NTESTS);

//   print_t("kyber_hash_pk: ", t_kp, NTESTS);
//   print_t("kyber_gen_a: ", t_enc, NTESTS);
//   print_t("kyber_unpack: ", t_dec, NTESTS);
// }

int main()
{
  
  // kyber_speed();

  //////////////////////////////////////////////////////////////////////
  
	rsa_speed();

  //////////////////////////////////////////////////////////////////////

  // ecdsa_speed();

  // kyber_kex();

  // rsa_kex();

  // special_test();

  return 0;
}
