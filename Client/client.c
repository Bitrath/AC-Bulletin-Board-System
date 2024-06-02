#define _POSIX_C_SOURCE 200809L
#define MAX_REQUEST_SIZE (64 * 1024)
#define NONCE_LEN 16
#define MAX_USER_CHAR 128
#include <netdb.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "../Utils/Dif_Hel.h"
#include "../Utils/digital_signature.h"
#include "../Utils/rxb.h"
#include "../Utils/utils.h"

void t_disconnect(int sd)
{
    close(sd);
    puts("--- <Disconnected from the server> ---");
}

void client_control(int sd)
{
    // --- CONTROLLO PRESENZA DELL'UTENTE TRA QUELLI REGISTRATI ---

    char user[MAX_USER_CHAR];
    ssize_t bytes_sent;

    memset(&user, 0, sizeof(user)); // inizializzo tutto il vettore a 0
    size_t user_len = sizeof(user) - 1;

    puts("Inserire il username: ");
    if (fgets(user, sizeof(user), stdin) < 0)
    {
        fprintf(stderr, "Errore fgets user");
        exit(EXIT_FAILURE);
    }
    else if (strlen(user) >= MAX_USER_CHAR - 1)
    {
        fprintf(stderr, "L'username inserito e' troppo lungo. (> 128 char)\n");
        exit(EXIT_FAILURE);
    }

    bytes_sent = send(sd, user, user_len, 0);

    if (bytes_sent < 0)
    {
        perror("Errore send");
        exit(EXIT_FAILURE);
    }
}

void *handshake(int sd)
{
    /*
    (CLIENT HANDSHAKE PROTOCOL)

    *** (PHASE 1) ***
    *** EPHEMERAL DIFFIE HELLMAN ***
    (CH1): [NONCEs]
         -> M1 to Server and M2 from Server.
    (CH2): [Ephemeral DIFFIE-HELLMAN Setup]
         -> <Client DH {PU, PR}> generation,
    (CH3): [DH PubKey Exchange]
         A) M3 and M4 receive from Server. {s_DH_PUk_len, s_DH_PUk}
         B) M5 and M6 to Server. {c_DH_PUk_len, c_DH_PUk}
    (CH4): [DH Shared Secret]
         -> Diffie-Hellman Shared Secret Derivation.
    (CH5): [Session Key Kab]
         -> Session Key {Kab} Derivation.

    *** (PHASE 2) ***
    *** CLIENT RSA VERIFICATION ***
    (C_RSA1): The client receives a message M, verifies the signature using the already known server's public RSA key.s

    *** (PHASE 3) ***
    *** CLIENT DIGITAL ENVELOPE VERIFICATION ***

    (HANDSHAKE PROTOCOL MESSAGES)
        {Client}  <-|->  {Server}
    M1: {nonce_c} -> {}
    M2: {} <- {nonce_s}
    M3: {} <- {s_DH_PUk_len}
    M4: {} <- {s_DH_PUk}
    M5: {s_DH_PUk_len} -> {}
    M6: {s_DH_PUk} -> {}
    M7: {} <- {E(H(nonce_c + s_DH_PUk), s_PRk_rsa)}
    M8: {} <- {s_certificate}
    M9: {ENVELOPE(nonce_s + c_DH_PUk), E(c_sym_k))} -> {}
    */

    printf("--- CLIENT HANDSHAKE with SERVER ----");

    //*** (PHASE 1) ***
    //*** EPHEMERAL DIFFIE HELLMAN ***

    // --> STEP (CH1)
    // (CH1): NONCEs Exchange

    // Client Nonce
    unsigned char *nonce_c = (unsigned char *)malloc(NONCE_LEN);
    RAND_poll();
    int rc = RAND_bytes(nonce_c, NONCE_LEN);
    if (rc != 1)
    {
        fprintf(stderr, "CLIENT Error: Failed to generate fresh nonce.");
        close(sd);
        exit(EXIT_FAILURE);
    }

    printf("\n(CH1): <Client Nonce> success.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_c[i]);
    }

    // (CH1): M1{nonce_c} -> Server
    ssize_t bytes_sent = send(sd, nonce_c, NONCE_LEN, 0);
    if (bytes_sent < 0)
    {
        perror("CLIENT Error: handshake -> send(nonce) failure.\n");
        free(nonce_c);
        close(sd);
        exit(EXIT_FAILURE);
    }
    printf("\n(CH1): <Client Nonce> to <Server>");

    // (CH1): M2{nonce_s} <- Server
    unsigned char *nonce_s = (unsigned char *)malloc(NONCE_LEN);
    ssize_t bytes_received = recv(sd, nonce_s, NONCE_LEN, 0);
    if (bytes_received < 0)
    {
        perror("CLIENT Error: handshake -> receive(Server nonce) failure.");
        free(nonce_c);
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Server Nonce
    printf("\n(CH1): <Server Nonce> received. \n->  ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_s[i]); // %x perche' lo voglio in hexadecimal
    }
    puts("");

    // --> STEP (CH2)
    // (CH2): Ephemeral DIFFIE-HELLMAN Client Setup

    // Client DH_Priv_Key
    EVP_PKEY *DHprivKey = DH_privkey();

    // Client DH_Pub_Key length: memory allocation
    uint32_t *len = (uint32_t *)malloc(sizeof(uint32_t));
    if (!len)
    {
        perror("CLIENT Error: handshake -> DH_PrivKey malloc() failure\n");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Client DH_Pub_Key
    unsigned char *DH_pubkeyPEM_c = DH_pub_key("dh_PUBKEY_client.pem", DHprivKey, len);
    if (!DH_pubkeyPEM_c)
    {
        perror("CLIENT Error: handshake -> failure when receiving Server PubKey string.");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        close(sd);
        exit(EXIT_FAILURE);
    }
    printf("(CH2): <Client Public Key> creation success.\n-> %s", DH_pubkeyPEM_c);

    // --> STEP (CH3)
    // (CH3): DH Keys Exchange

    // Server DH_Pub_Key length: memory allocation
    uint32_t *DH_pubkeyLEN_s = (uint32_t *)malloc(sizeof(uint32_t));

    // (CH3): M3{s_DH_PUk_len} <- Server
    bytes_received = recv(sd, DH_pubkeyLEN_s, sizeof(uint32_t), 0);
    if (bytes_received <= 0)
    {
        perror("CLIENT Error: handshake() -> recv() -> Server PukKey length error.\n");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        free(DH_pubkeyPEM_c);
        close(sd);
        exit(EXIT_FAILURE);
    }

    printf("\n -- TEST SPUBKEY LEN (%u)", *DH_pubkeyLEN_s);

    /*
    (NO) unsigned char *DH_pubkeyPEM_s = malloc((size_t)len + 1);
    (OK) unsigned char *DH_pubkeyPEM_s = (unsigned char*)malloc((*len + 1) * sizeof(unsigned char));
    bytes_received = recv(sd, DH_pubkeyPEM_s, *len, 0);
    */

    // Server DH_Pub_Key buffer: memory allocation
    unsigned char *DH_pubkeyPEM_s = (unsigned char *)malloc(*DH_pubkeyLEN_s);
    if (!DH_pubkeyPEM_s)
    {
        perror("CLIENT Error: handshake() -> Pub Key memory allocation failure.\n");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        free(DH_pubkeyPEM_c);
        free(DH_pubkeyLEN_s);
        close(sd);
        exit(EXIT_FAILURE);
    }

    // (CH3): M4{s_DH_PUk} <- Server [G^b]
    bytes_received = recv(sd, DH_pubkeyPEM_s, *DH_pubkeyLEN_s, 0);
    if (bytes_received < 0)
    {
        perror("CLIENT Error: handshake() -> Server PubKey recv(9 failure.\n");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        free(DH_pubkeyPEM_c);
        free(DH_pubkeyLEN_s);
        close(sd);
        exit(EXIT_FAILURE);
    }
    printf("(CH3): <Server Public Key> reception success.\n-> %s", DH_pubkeyPEM_s);

    // Client DH_Pub_Key Length
    uint32_t DHpubkeyLEN = *len;

    // (CH3): M5{c_DH_PUk_len} -> Server
    bytes_sent = send(sd, len, sizeof(uint32_t), 0);
    if (bytes_sent < 0)
    {
        perror("CLIENT Error: handshake() -> Client_PubKey_lenght send() failure.\n");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        free(DH_pubkeyPEM_c);
        free(DH_pubkeyLEN_s);
        free(DH_pubkeyPEM_s);
        close(sd);
        exit(EXIT_FAILURE);
    }

    // (CH3): M6{c_DH_PUk} -> Server [G^a]
    if ((bytes_sent = send(sd, DH_pubkeyPEM_c, *len, 0)) < 0)
    {
        perror("CLIENT Error: handshake() -> Client_PubKey send() failure.\n");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        free(DH_pubkeyPEM_c);
        free(DH_pubkeyLEN_s);
        free(DH_pubkeyPEM_s);
        close(sd);
        exit(EXIT_FAILURE);
    }
    printf("(CH3): <Client Public Key> to <Server>.\n");

    // (Server_DH_Pub_Key).PEM
    const char *filepath = "ServerPubKey.pem";
    EVP_PKEY *DHpubKey_s = DH_derive_pubkey(filepath, DH_pubkeyPEM_s, *DH_pubkeyLEN_s);
    if (DHpubKey_s == NULL)
    {
        perror("CLIENT Error: handshake() -> Server_PubKey derivation failure.\n ");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        free(DH_pubkeyPEM_c);
        free(DH_pubkeyLEN_s);
        free(DH_pubkeyPEM_s);
        close(sd);
        exit(EXIT_FAILURE);
    }

    // --> STEP (CH4)
    // (CH4): Diffie-Hellman Shared Secret Derivation

    // Client Secret Length: To retrieve the shared secret’s length after the DH_derive_shared_secret call
    size_t shared_secret_len;

    // Client DH Secret
    unsigned char *secret = DH_derive_shared_secret(DHprivKey, DHpubKey_s, &shared_secret_len);
    if (!secret)
    {
        perror("CLIENT Error: (SH4) shared_secret_creation() failure.\n");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        free(DH_pubkeyPEM_c);
        free(DH_pubkeyLEN_s);
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHpubKey_s);
        close(sd);
        exit(EXIT_FAILURE);
    }
    printf("(CH4): <Client Secret>\n-> %hhu \n", *secret);

    // --> STEP (CH5)
    // (CH5): Session Key {Kab} Derivation.

    // Client Session Key Length
    unsigned int skl = 0;
    unsigned int *session_key_length = &skl;

    // Client Session Key
    unsigned char *session_key = create_session_key(EVP_sha256(), EVP_aes_128_gcm(), secret, shared_secret_len, session_key_length); // prima passavo l'indirizzo ed era errato
    if (!session_key)
    {
        perror("CLIENT Error: (CH5) create_session_key() failure.\n");
        free(nonce_c);
        EVP_PKEY_free(DHprivKey);
        free(len);
        free(DH_pubkeyPEM_c);
        free(DH_pubkeyLEN_s);
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHpubKey_s);
        free(secret);
        close(sd);
        exit(EXIT_FAILURE);
    }
    printf("(CH5): <Client Session Key>\n-> %hhu\n", *session_key);

    /*
    // Memory Cleaning
    free(len);
    free(secret);
    free(DH_pubkeyPEM_c);
    free(DH_pubkeyPEM_s);
    free(DH_pubkeyLEN_s);
    EVP_PKEY_free(DHprivKey);
    EVP_PKEY_free(DHpubKey_s);
    */ 

    // *** END (PHASE 1) ***

    // *** BEGIN (PHASE 2) ***

    // --> STEP (C_RSA1)
    // (C_RSA1): Client Receives two messages:
    //  -> M7: Signature length
    //  -> M8: Signature

    // M7: server_signature_length
    uint32_t *server_sig_length = (u_int32_t *)malloc(sizeof(u_int32_t));

    bytes_received = recv(sd, server_sig_length, sizeof(u_int32_t), 0);
    
    if (bytes_received <= 0)
    {
        perror("CLIENT Error: (C_RSA1) server_signature_length receive failure.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Server RSA+SHA256 Signature
    // M8: M = {nonce_c||s_DH_PUk}. Y = M7 = E{H(M), Server_PrivKey_RSA}
    unsigned char *server_signature = (unsigned char *)malloc(*server_sig_length);

    bytes_received = recv(sd, server_signature, *server_sig_length, 0);

    if (bytes_received <= 0)
    {
        perror("CLIENT Error: (C_RSA1) server_signature receive failure.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    printf("(S_RSA1): <Server RSA+SHA256 Signature>\n-> ");

    for (int i = 0; i < *server_sig_length; i++)
    {
        printf("%x ", server_signature[i]);
    }

    // --> STEP (C_RSA2)
    // (C_RSA2): Client verifies Server_Signature with Server_RSA_PubKey already known.

    const char *server_pubkey_rsa_filepath = "Client-Wallet/server_pubkey_rsa.pem";

    // Server RSA_Pub_Key
    EVP_PKEY *server_pubkey_rsa = Public_RSA_Key_From_File(server_pubkey_rsa_filepath);
    if (!server_pubkey_rsa)
    {
        perror("CLIENT Error: RSA Public Key read failure.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    uint32_t dh_server_pubkey_size = *DH_pubkeyLEN_s;
    unsigned char *test_signature = (unsigned char *)malloc(NONCE_LEN + dh_server_pubkey_size);
    if (!test_signature)
    {
        perror("CLIENT Error: Test Signature malloc() failure.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }
    memcpy(test_signature, nonce_c, NONCE_LEN);
    memcpy(test_signature + NONCE_LEN, DH_pubkeyPEM_s, *DH_pubkeyLEN_s);

    size_t test_sig_length = (size_t)(NONCE_LEN + *DH_pubkeyLEN_s);
    printf("\nSIZES: signature(%u) test_message(%u)", *server_sig_length, test_sig_length);

    //printf("\n(TEST M): <nonce_c + dh_s_pk>\n-> %hhu\n", *test_signature);

    int verify_result = VerifySignatureWithRSA(EVP_sha256(), server_signature, *server_sig_length, server_pubkey_rsa, test_signature, test_sig_length);
    if (verify_result == 0)
    {
        perror("CLIENT Error: (Server Signature) NOT VALID.\n");
        free(server_signature);
        free(server_sig_length);
        close(sd);
        exit(EXIT_FAILURE);
    } 
    printf("\n(S_RSA2): SIGNATURE is OK BRUH -> (%u)\n", verify_result);

    printf("--- END CLIENT HANDSHAKE with SERVER ---");

    return session_key;
}

int main(int argc, char **argv)
{
    int err, sd;
    struct addrinfo hints, *res, *ptr;

    if (argc != 3)
    {
        fprintf(stderr, "\nCLIENT Error: arguments failure. Run as: ./client host port \n");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((err = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0)
    {
        fprintf(stderr, "CLIENT Error: main() -> (getaddrinfo) failure\n");
        exit(EXIT_FAILURE);
    }

    for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
        if ((sd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol)) < 0)
        {
            fprintf(stderr, "CLIENT Error: main() -> (socket) failure\n");
            continue;
        }

        if (connect(sd, ptr->ai_addr, ptr->ai_addrlen) == 0)
        {
            puts("(C0): <Connection> to <Server> success.");
            break;
        }

        close(sd);
    }

    if (ptr == NULL)
    {
        fprintf(stderr, "CLIENT Error: main() -> (fallback) failure\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    unsigned char *K_ab = handshake(sd);

    close(sd);
    return 0;
}