#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

EVP_PKEY* DH_privkey();
unsigned char *DH_pub_key(char *filename, EVP_PKEY *prvKey, uint32_t *file_len);
void handleErrors();
