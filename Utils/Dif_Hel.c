#include "Dif_Hel.h"

EVP_PKEY *DH_privkey()
{
  // (dh_params): a set of DH parameters, or a pair of DH public/private keys
  EVP_PKEY *dh_params = EVP_PKEY_new();
  if (!dh_params)
  {
    return NULL;
  }

  DH *low_params = DH_get_2048_224();
  if (!EVP_PKEY_set1_DH(dh_params, low_params))
  {
    EVP_PKEY_free(dh_params);
    return NULL;
  }

  /* Generation of private/public key pair */

  // EVP_PKEY_CTX = context for public-key operations
  /* Allocate a context for public-key operations using algorithm pkey
      – If pkey represents DH parameters, the operation is a key generation (this case)
      – If pkey represents DH private key, the operation is a secret derivation */
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(dh_params, NULL);
  if (!ctx)
  {
    EVP_PKEY_free(dh_params);
    return NULL;
  }

  EVP_PKEY *my_prvkey = NULL; // init private key
  if (!EVP_PKEY_keygen_init(ctx))
  {
    // Initialize a context for Diffie-Hellman key generation. Returns 1 on success.
    perror("Error: init context");
    EVP_PKEY_free(dh_params);
    EVP_PKEY_CTX_free(ctx);
    return NULL;
  }

  if (!EVP_PKEY_keygen(ctx, &my_prvkey))  // generazione chiave privata
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
@function (DH_pub_key): Writes in a (filename).PEM the PUB_KEY derived from (prvKey). 

@param (filename): where to write the PUB_KEY. It's a (.PEM) filetype.
@param (prvKey): a Private Key instance, belonging to a (PUk, PRk) key pair. 
@param (file_len): pointer to the file length.

@return (buffer_pubKey): the PUk of the .PEM file in a string format.
*/
unsigned char *DH_pub_key(char *filename, EVP_PKEY *prvKey, uint32_t *file_len)
{
  FILE *pubkey_PEM = fopen(filename, "w+");
  if (!pubkey_PEM)
  {
    perror("Errore nell'apertura del file PEM");
    return NULL;
  }

  // creazione file pem con derivazione della chiave pubblica da quella privata

  int err = PEM_write_PUBKEY(pubkey_PEM, prvKey);
  if (err != 1)
  {
    perror("Errore nell'apertura del file PEM");
    return NULL;
  }

  // Save File Lenght. Move FILE Pointer to the END, read the offset, than return to the beginning.
  fseek(pubkey_PEM, 0, SEEK_END);
  *file_len = (uint32_t)ftell(pubkey_PEM);
  rewind(pubkey_PEM);

  // buffer dynamic size creation, where the pubKey in bytes will be read and stored.

  unsigned char *buffer_pubKey = (unsigned char *)malloc((size_t)*file_len);
  if (!buffer_pubKey)
  {
    perror("Errore nella creazione del buffer_pubKey");
    fclose(pubkey_PEM);
    return NULL;
  }

  // leggo il file PEM con la chiave pubblica
  err = fread(buffer_pubKey, 1, (size_t) *file_len, pubkey_PEM);
  if (err < *file_len)
  {
    perror("Errore nella lettura del file PEM");
    fclose(pubkey_PEM);
    free(buffer_pubKey);
    return NULL;
  }
  fclose(pubkey_PEM);
  return buffer_pubKey;
}
