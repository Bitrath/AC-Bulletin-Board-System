#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdbool.h>

// RSA
EVP_PKEY *Private_RSA_Key_From_File(const char *filepath);
EVP_PKEY *Public_RSA_Key_From_File(const char *filepath);
unsigned char *SignatureWithRSA(const EVP_MD *hash_type, unsigned char *message, size_t message_length, EVP_PKEY *rsa_privkey, uint32_t *signature_length);
int VerifySignatureWithRSA(const EVP_MD* hash_type, unsigned char* signature, unsigned int sign_len, EVP_PKEY* rsa_pub_key, unsigned char* to_check, size_t to_check_len);