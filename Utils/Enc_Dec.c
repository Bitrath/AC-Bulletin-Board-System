#include "Enc_Dec.h"

int encrypt_data(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  int ciphertext_len = 0;

  if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
  {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
  {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  ciphertext_len = len;

  if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
  {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  ciphertext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt_data(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  int len = 0;
  int plaintext_len = 0;

  if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
  {
    ERR_print_errors_fp(stderr);
    return -1;
  }

  if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
  {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  plaintext_len = len;

  if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
  {
    ERR_print_errors_fp(stderr);
    return -1;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

