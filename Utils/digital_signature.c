#include "digital_signature.h"

EVP_PKEY *Private_RSA_Key_From_File(const char *filepath)
{
    FILE *rsa_file = fopen(filepath, "r");
    if (!rsa_file)
    {
        return NULL;
    }
    EVP_PKEY *rsa_key = PEM_read_PrivateKey(rsa_file, NULL, NULL, NULL);
    fclose(rsa_file);
    return rsa_key;
}

EVP_PKEY *Public_RSA_Key_From_File(const char *filepath)
{
    FILE *rsa_file = fopen(filepath, "r");
    if (!rsa_file)
    {
        return NULL;
    }
    EVP_PKEY *rsa_key = PEM_read_PUBKEY(rsa_file, NULL, NULL, NULL);
    fclose(rsa_file);
    return rsa_key;
}

unsigned char *SignatureWithRSA(const EVP_MD *hash_type, unsigned char *message, size_t message_length, EVP_PKEY *rsa_privkey, uint32_t *signature_length)
{
    unsigned char *ciphertext = (unsigned char *)malloc(EVP_PKEY_size(rsa_privkey));
    if (!ciphertext)
    {
        return NULL;
    }
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return NULL;
    }
    if (!EVP_SignInit(ctx, hash_type))
    {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    // if(!EVP_DigestUpdate(ctx, message, size_t(message_length))); //che size_t passo???
    if (!EVP_SignUpdate(ctx, message, message_length))
    {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    if (!EVP_SignFinal(ctx, ciphertext, signature_length, rsa_privkey))
    {
        EVP_MD_CTX_free(ctx);
        return NULL;
    }
    EVP_MD_CTX_free(ctx);
    return ciphertext;
}

int VerifySignatureWithRSA(const EVP_MD *hash_type, unsigned char *signature, uint32_t sign_len, EVP_PKEY *rsa_pub_key, unsigned char *to_check, size_t to_check_len)
{
    int result = 0; // Default to failure
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return 0;
    }
    
    if (!EVP_VerifyInit(ctx, hash_type))
    {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    if (!EVP_VerifyUpdate(ctx, to_check, to_check_len))
    {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    
    result = EVP_VerifyFinal(ctx, signature, (unsigned int)sign_len, rsa_pub_key);
    EVP_MD_CTX_free(ctx);
    
    if (result != 1)
    {
        return 0; // Verification failed
    }
    
    return 1; // Verification succeeded
}
