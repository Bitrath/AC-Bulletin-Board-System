#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

EVP_PKEY* DH_privkey();
void handleErrors();
