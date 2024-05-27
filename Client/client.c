#include <netdb.h>
#include <stdio.h>
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
#include "../Utils/rxb.h"
#include "../Utils/utils.h"

#define _POSIX_C_SOURCE 200809L
#define MAX_REQUEST_SIZE (64 * 1024)
#define NONCE_LEN 16
#define MAX_USER_CHAR 128


void t_disconnect(int sd)
{
    close(sd);
    puts("\n-----(Disconnected from the server)-----\n");
    pthread_exit(NULL);
}

void client_control(int sd)
{
    // --- CONTROLLO PRESENZA DELL'UTENTE TRA QUELLI REGISTRATI ---

    char user[MAX_USER_CHAR];
    ssize_t bytes_sent;

    memset(&user, 0, sizeof(user)); // inizializzo tutto il vettore a 0
    size_t user_len = sizeof(user) - 1;

    puts("Username: ");
    if (fgets(user, sizeof(user), stdin) < 0)
    {
        fprintf(stderr, "CLIENT Error: User fgets() failure\n");
        exit(EXIT_FAILURE);
    }
    else if (strlen(user) >= MAX_USER_CHAR - 1) // informati su strnlen
    {
        fprintf(stderr, "CLIENT Error: Username too long. (> 128 char)\n");
        exit(EXIT_FAILURE);
    }

    bytes_sent = send(sd, user, user_len, 0);

    if (bytes_sent < 0)
    {
        perror("CLIENT Error: client_control->send() failure");
        exit(EXIT_FAILURE);
    }
}

void *handshake(int sd)
{
    /* ------------------------------------
       1) SCAMBIO NONCE CON IL SERVER
       ------------------------------------ */

    unsigned char nonce_c[NONCE_LEN];
    RAND_poll();                                   // context init
    int rc = RAND_bytes(nonce_c, sizeof(nonce_c)); // nonce del client creato con successo
    if (rc != 1)
    {
        fprintf(stderr, "CLIENT Error: Failed to generate fresh nonce.");
        exit(EXIT_FAILURE);
    }

    printf("\nClient < nonce created >\n-> ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_c[i]);
    }
    puts("\nClient: < sending nonce to Server >\n");

    ssize_t bytes_sent = send(sd, nonce_c, sizeof(nonce_c), 0); // con la rxb non si riesce perchè comunica solo in char
                                                                // piu' comode la send e rcv
    if (bytes_sent < 0)
    {
        perror("CLIENT Error: handshake -> send(nonce) failure.\n");
        exit(EXIT_FAILURE);
    }

    // --- RICEZIONE NONCE DEL SERVER ---

    unsigned char nonce_s[NONCE_LEN];
    ssize_t bytes_received = recv(sd, nonce_s, sizeof(nonce_s), 0);

    if (bytes_received < 0)
    {
        perror("CLIENT Error: handshake -> receive(Server nonce) failure.");
        close(sd);
        pthread_exit(NULL);
    }

    printf("\nClient: < Server Nonce received >\n->  ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_s[i]); // %x perche' e' in bytes
    }
    puts("");

    /* ------------------------------------
       2) CREAZIONE CHIAVE PRIVATA E PUBBLICA
       ------------------------------------ */

    // --- CREAZIONE CHIAVE PRIVATA CLIENT ---

    EVP_PKEY *DHprivKey = DH_privkey();

    uint32_t *len;
    len = (uint32_t *)malloc(sizeof(uint32_t));

    if (!len)
    {
        perror("CLIENT Error: handshake -> DH_PrivKey malloc() failure\n");
        EVP_PKEY_free(DHprivKey);
        free(len);
        t_disconnect(sd);
    }

    unsigned char *DH_pubkeyPEM_c = DH_pub_key("dh_PUBKEY_client.pem", DHprivKey, len);

    printf("\nClient: <Client Public Key> success.\n-> %s\n", DH_pubkeyPEM_c);

    if (!DH_pubkeyPEM_c)
    {
        perror("CLIENT Error: handshake -> failure when receiving Server PubKey string.");
        EVP_PKEY_free(DHprivKey);
        free(len);
        t_disconnect(sd);
    }

    uint32_t *DH_pubkeyLEN_s = (uint32_t *)malloc(sizeof(uint32_t));

    // Ricezione della lunghezza della chiave pubblica del server
    bytes_received = recv(sd, DH_pubkeyLEN_s, sizeof(uint32_t), 0);
    if (bytes_received <= 0)
    {
        perror("CLIENT Error: handshake() -> recv() -> Server PukKey length error.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Allocazione memoria per la DH_pubkeyPEM_s proveniente dal server

    unsigned char *DH_pubkeyPEM_s = malloc((size_t)len + 1);
    if (!DH_pubkeyPEM_s)
    {
        perror("CLIENT Error: handshake() -> Pub Key memory allocation failure.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // (NICO) Why there's a rewrite on bytes_received?

    // RICEVO G^b DAL SERVER

    bytes_received = recv(sd, DH_pubkeyPEM_s, *len, 0);

    if (bytes_received < 0)
    {
        perror("CLIENT Error: handshake() -> Server PubKey recv(9 failure.\n");
        close(sd);
        pthread_exit(NULL);
    }

    printf("\nClient: <Server Public Key> reception success.\n-> %s\n", DH_pubkeyPEM_s);

    /////////////////////////
    // INVIO G^a AL SERVER //
    /////////////////////////

    puts("\nClient: NEXT STEP -> <Client Public Key> to <Server>\n\n");

    uint32_t DHpubkeyLEN = *len;

    // Invia la lunghezza della chiave pubblica al SERVER
    bytes_sent = send(sd, len, sizeof(uint32_t), 0);
    if (bytes_sent < 0)
    {
        perror("CLIENT Error: handshake() -> Client_PubKey_lenght send() failure.\n");
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        close(sd);
        exit(EXIT_FAILURE);
    }

    // INVIO la chiave AL SERVER

    if ((bytes_sent = send(sd, DH_pubkeyPEM_c, *len, 0)) < 0)
    {
        perror("CLIENT Error: handshake() -> Client_PubKey send() failure.\n");
        exit(EXIT_FAILURE);
    }

    // generazione dinamica del file PEM contenente la chiave pubblica del server

    const char *filepath = "ServerPubKey.pem";
    EVP_PKEY *DHpubKey_s = DH_derive_pubkey(filepath, DH_pubkeyPEM_s, *DH_pubkeyLEN_s);

    if (DHpubKey_s == NULL)
    {
        perror("CLIENT Error: handshake() -> Server_PubKey derivation failure.\n ");
        EVP_PKEY_free(DHprivKey);
        free(DH_pubkeyPEM_c);
        free(DH_pubkeyLEN_s);
        free(DH_pubkeyPEM_s);

        t_disconnect(sd);
    }

    ////////////////////////////////////////
    /// Derivo la chiave di sessione Kab ///
    ////////////////////////////////////////

    // To retrieve the shared secret’s length after the DH_derive_shared_secret call
    size_t session_key_len;

    // derivation of the shared secret
    unsigned char *secret = DH_derive_shared_secret(DHprivKey, DHpubKey_s, &session_key_len);
    //puts(secret);

    return 0;
}

int main(int argc, char **argv)
{
    int err, sd;
    struct addrinfo hints, *res, *ptr;

    if (argc != 3)
    {
        fprintf(stderr, "\nCLIENT Error: arguments failure. Write as: ./client host port \n");
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_IGN);

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
            puts("Client: <Connection> to <Server> success.\n");
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