#include "Dif_Hel.h"

EVP_PKEY *DH_privkey()
{
  // EVP_PKEY = set of DH parameters or a pair of DH public/private keys
  EVP_PKEY *dh_params = EVP_PKEY_new();

  EVP_PKEY_set1_DH(dh_params, DH_get_2048_224());

  /* Generation of private/public key pair */

  // EVP_PKEY_CTX = context for public-key operations
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dh_params, NULL);
  /* Allocate a context for public-key operations using algorithm pkey
      – If pkey represents DH parameters, the operation is a key generation (this case)
      – If pkey represents DH private key, the operation is a secret derivation */

  EVP_PKEY *my_prvkey = NULL; // init private key

  if (EVP_PKEY_keygen_init(ctx) != 1) // Initialize a context for Diffie-Hellman key generation.
  {                                   // Returns 1 on success.
    perror("Error: init context");
    EVP_PKEY_free(dh_params);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (EVP_PKEY_keygen(ctx, &my_prvkey) != 1)
  {
    perror("Error: private key generation unsuccessful");
    EVP_PKEY_free(dh_params);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  EVP_PKEY_CTX_free(ctx);
  EVP_PKEY_free(dh_params);
  return my_prvkey;
}
/*
unsigned *char DH_pub_key(string filepath, EVP_PKEY* prvKey)
{
}
*/
