#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#define EVP_MAX_IV_LENGTH 128

/////// NOT SURE IF NEEDED ///////

int EVP_SealInit(EVP_CIPHER_CTX* ctx, const EVP_CIPHER* type, unsigned char** ek, int* ekl, unsigned char* iv, EVP_PKEY** pubk, int npubk);
int EVP_SealUpdate(EVP_CIPHER_CTX* ctx, unsigned char* out, int* outl, unsigned char* in, int inl);