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

  if (!EVP_PKEY_keygen(ctx, &my_prvkey)) // generazione chiave privata
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
  // leggo con fread perche' necessito il formato unsigned char per poter trasmettere al client/server
  err = fread(buffer_pubKey, 1, (size_t)*file_len, pubkey_PEM);
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

// deriva la chiave pubblica dal file PEM
EVP_PKEY *DH_derive_pubkey(const char *filename, unsigned char *buffer, uint32_t file_len)
{

  // apro un file PEM in scrittura per poter scrivere la chiave pubblica
  FILE *pubkey_PEM = fopen(filename, "w+");
  if (!pubkey_PEM)
  {
    perror("Errore nell'apertura del file PEM");
    return NULL;
  }

  // scrivo la chiave pubblica ricevuta nel file PEM (1 e' la dimensione in byte di ogni elemento del buffer)
  uint32_t err = fwrite(buffer, 1, file_len, pubkey_PEM);
  if (err < file_len)
  {
    perror("Errore scrittura del file PEM");
    fclose(pubkey_PEM);
    return NULL;
  }

  fseek(pubkey_PEM, 0, SEEK_SET);
  // al posto della lettura con fread, uso PEM_read_PUBKEY, in modo tale che restituisca un tipo EVP_KEY *
  EVP_PKEY *received_pubkey = PEM_read_PUBKEY(pubkey_PEM, NULL, NULL, NULL);

  if (received_pubkey == NULL)
  {
    perror("Errore nella lettura della chiave pubblica ricevuta");
    fclose(pubkey_PEM);
    return NULL;
  }
  fclose(pubkey_PEM);

  return received_pubkey;
}

unsigned char *DH_derive_shared_secret(EVP_PKEY *privkey, EVP_PKEY *received_pubkey, size_t *secret_len)
{

  EVP_PKEY *peer_pubkey;
  unsigned char *secret;
  uint32_t err;

  // Initializing shared secret derivation context
  EVP_PKEY_CTX *ctx_drv = EVP_PKEY_CTX_new(privkey, NULL);

  // Initializes a context for Diffie-Hellman secret derivation. Returns 1 on success.
  err = EVP_PKEY_derive_init(ctx_drv);

  if (err != 1)
  {
    EVP_PKEY_CTX_free(ctx_drv);
    perror("Errore nell'init del ctx del segreto DH");
    return NULL;
  }

  // Sets the peer’s public key for Diffie-Hellman secret derivation. Returns 1 on success.
  err = EVP_PKEY_derive_set_peer(ctx_drv, received_pubkey);

  if (err != 1)
  {
    EVP_PKEY_CTX_free(ctx_drv);
    perror("Errore nel set del peer della pubKey per la derivazione del segreto DH");
    return NULL;
  }

  // Sets the maximum size of the Diffie-Hellman shared secret to be derived in *secretlen. Returns 1 on success

  err = EVP_PKEY_derive(ctx_drv, NULL, secret_len);

  if (err != 1)
  {
    EVP_PKEY_CTX_free(ctx_drv);
    perror("Errore nella derivazione dello spazio massimo del segreto DH");
    return NULL;
  }

  secret = (unsigned char *)malloc(*secret_len);

  if (!secret)
  {
    EVP_PKEY_CTX_free(ctx_drv);
    perror("Errore malloc");
    return NULL;
  }
  err = EVP_PKEY_derive(ctx_drv, secret, secret_len);

  if (err != 1)
  {
    EVP_PKEY_CTX_free(ctx_drv);
    return NULL;
  }
  EVP_PKEY_CTX_free(ctx_drv);
  return secret;
}

unsigned char *create_session_key(const EVP_MD *hash_type, const EVP_CIPHER *cipher_type, unsigned char *s, size_t s_len, unsigned int *hash_len)
{
  // hash = SHA256(secret);
  unsigned char *hash = (unsigned char *)malloc(EVP_MD_size(hash_type));
  if (!hash)
  {
    perror("Error at assignment: unsigned char *hash = (unsigned char*)malloc(EVP_MD_size(hash_type));");
    return NULL;
  }
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
  {
    free(hash);
    return NULL;
  }
  if (!EVP_DigestInit(ctx, hash_type))
  {
    free(hash);
    EVP_MD_CTX_free(ctx);
    return NULL;
  }
  if (!EVP_DigestUpdate(ctx, s, s_len))
  {
    EVP_MD_CTX_free(ctx);
    free(hash);
    return NULL;
  }
  if (!EVP_DigestFinal(ctx, hash, hash_len))
  {
    free(hash);
    EVP_MD_CTX_free(ctx);
    return NULL;
  }
  EVP_MD_CTX_free(ctx);

  // k_ab_AES128 = hash[ AES128_len || ... ];
  unsigned char *sk = (unsigned char *)malloc(EVP_CIPHER_key_length(cipher_type));

  if (!sk)
  {
    free(hash);
    return NULL;
  }

  if (*hash_len > (unsigned int)EVP_CIPHER_key_length(cipher_type))
  {
    memcpy(sk, hash, EVP_CIPHER_key_length(cipher_type));
    free(hash);
    *hash_len = EVP_CIPHER_key_length(cipher_type);
    return sk;
  }
  return hash;
}