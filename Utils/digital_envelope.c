#include "digital_envelope.h"

/////// NOT SURE IF NEEDED ///////

unsigned char *envelope_creation(unsigned char *nonce, EVP_CIPHER *cipher)
{
  // EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  // EVP_CIPHER *cipher = EVP_aes_128_gcm() unsigned char * ek[2];

  unsigned char key[128];
  unsigned char iv[128];
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

  // Genera una chiave casuale di 128 byte
  if (RAND_bytes(key, sizeof(key)) != 1)
  {
    fprintf(stderr, "Errore nella generazione della chiave\n");
    return NULL;
  }

  // Genera un IV casuale di 128 byte
  if (RAND_bytes(iv, sizeof(iv)) != 1)
  {
    fprintf(stderr, "Errore nella generazione dell'IV\n");
    return NULL;
  }

  EVP_EncryptInit(ctx, EVP_aes_128_ecb(), key, iv);

  // pubk deve essere inizializzato con le chiavi pubbliche dei destinatari

  err = EVP_SealInit(ctx, cipher, ek, ekl, iv, pubk, npubk);

  if (err == 0)
  {
    perror("Errore EVP_SealInit\n");
    free(ctx);
    free(cipher);
    return NULL;
  }

  err = int EVP_SealUpdate(EVP_CIPHER_CTX * ctx, unsigned char *out, int *outl, unsigned char *in, int inl);
}

/*
    Client  |||  Server
M9: {ENVELOPE(nonce_s + c_DH_PUk), E(c_sym_k))} -> {}
*/