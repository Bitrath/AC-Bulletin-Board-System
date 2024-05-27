#ifndef DIF_HEL
#define DIF_HEL

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

void handleErrors();
EVP_PKEY *DH_privkey();
unsigned char *DH_pub_key(char *filename, EVP_PKEY *prvKey, uint32_t *file_len);
EVP_PKEY *DH_derive_pubkey(const char *filename, unsigned char *buffer, uint32_t file_len);
unsigned char *DH_derive_shared_secret(EVP_PKEY *my_privkey, EVP_PKEY *received_pubkey, size_t *secret_len);

#endif // DIF_HEL