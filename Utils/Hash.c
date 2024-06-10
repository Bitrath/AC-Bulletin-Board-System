#include "Hash.h"

void hash(const char *password, unsigned char digest[EVP_MAX_MD_SIZE], unsigned char *salt, size_t salt_size)
{
  unsigned int digestlen;
  EVP_MD_CTX *ctx;

  // Concatenazione password e salt
  size_t password_len = strlen(password);
  size_t total_len = password_len + salt_size;
  unsigned char *password_salt_concat = (unsigned char *)malloc(total_len);

  memcpy(password_salt_concat, password, password_len);
  memcpy(password_salt_concat + password_len, salt, salt_size);

  // Context allocation
  ctx = EVP_MD_CTX_new();
  if (ctx == NULL)
  {
    fprintf(stderr, "Errore nell'allocazione del contesto di hashing.\n");
    return;
  }

  // Hashing (initialization + single update + finalization)
  if (EVP_DigestInit(ctx, EVP_sha256()) != 1)
  {
    fprintf(stderr, "Errore nell'inizializzazione del contesto di hashing.\n");
    EVP_MD_CTX_free(ctx);
    return;
  }

  if (EVP_DigestUpdate(ctx, (unsigned char *)password, strlen(password)) != 1)
  {
    fprintf(stderr, "Errore nell'aggiornamento del contesto di hashing.\n");
    EVP_MD_CTX_free(ctx);
    return;
  }

  if (EVP_DigestFinal(ctx, digest, &digestlen) != 1)
  {
    fprintf(stderr, "Errore nella finalizzazione del contesto di hashing.\n");
    EVP_MD_CTX_free(ctx);
    return;
  }

  // Context deallocation
  EVP_MD_CTX_free(ctx);

  // Print digest in hexadecimal format
  printf("SHA-256 hash: ");
  for (unsigned int i = 0; i < digestlen; i++)
  {
    printf("%02x", digest[i]);
  }
  printf("\n");
}
