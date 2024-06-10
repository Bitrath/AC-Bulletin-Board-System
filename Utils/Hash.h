#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void hash(const char *msg, unsigned char digest[EVP_MAX_MD_SIZE], unsigned char *salt, size_t salt_size);