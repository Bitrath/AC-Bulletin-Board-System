#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

void handleErrors();
EVP_PKEY *DH_privkey();
unsigned char *DH_pub_key(char *filename, EVP_PKEY *prvKey, uint32_t *file_len);
EVP_PKEY *DH_derive_pubkey(const char *filename, unsigned char *buffer, uint32_t file_len);
unsigned char *DH_derive_shared_secret(EVP_PKEY *my_privkey, EVP_PKEY *received_pubkey, size_t *secret_len);
unsigned char *create_session_key(const EVP_MD *hash_structure, const EVP_CIPHER *cipher_structure, unsigned char *s, size_t s_len, unsigned int *hash_len);
