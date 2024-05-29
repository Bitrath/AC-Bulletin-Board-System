#define _POSIX_C_SOURCE 200809L
#define MAX_REQUEST_SIZE (64 * 1024)
#define NONCE_LEN 16
#define MAX_USER_CHAR 128
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

void t_disconnect(int sd)
{
    close(sd);
    puts("Disconnected from the server.");
    pthread_exit(NULL);
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
    /* ------------------------------------
       1) SCAMBIO NONCE CON IL SERVER
       ------------------------------------ */

    unsigned char nonce_c[NONCE_LEN];
    RAND_poll();                                   // context init
    int rc = RAND_bytes(nonce_c, sizeof(nonce_c)); // nonce del client creato con successo
    if (rc != 1)
    {
        fprintf(stderr, "Errore creazione nonce");
        exit(EXIT_FAILURE);
    }

    printf("Calcolato il nonce client: ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_c[i]);
    }
    puts("\nInvio il nonce del client al server...");

    ssize_t bytes_sent = send(sd, nonce_c, sizeof(nonce_c), 0); // con la rxb non si riesce perchè comunica solo in char
                                                                // piu' comode la send e rcv
    if (bytes_sent < 0)
    {
        perror("Errore send");
        exit(EXIT_FAILURE);
    }

    // --- RICEZIONE NONCE DEL SERVER ---

    unsigned char nonce_s[NONCE_LEN];
    ssize_t bytes_received = recv(sd, nonce_s, sizeof(nonce_s), 0);

    if (bytes_received < 0)
    {
        perror("Errore recv nonce del server");
        close(sd);
        pthread_exit(NULL);
    }

    printf("Nonce del server ricevuto: ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_s[i]); // %x perche' lo voglio in hexadecimal
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
        perror("Errore nella malloc");
        EVP_PKEY_free(DHprivKey);
        free(len);
        t_disconnect(sd);
    }

    unsigned char *DH_pubkeyPEM_c = DH_pub_key("dh_PUBKEY_client.pem", DHprivKey, len);

    printf("Creata la chiave pubblica del client: %s\n", DH_pubkeyPEM_c);

    if (!DH_pubkeyPEM_c)
    {
        perror("Errore nella ricezione della stringa contenente la pubKey");
        EVP_PKEY_free(DHprivKey);
        free(len);
        t_disconnect(sd);
    }

    uint32_t *DH_pubkeyLEN_s = (uint32_t *)malloc(sizeof(uint32_t));

    // Ricezione della lunghezza della chiave pubblica del server
    bytes_received = recv(sd, DH_pubkeyLEN_s, sizeof(uint32_t), 0);
    if (bytes_received <= 0)
    {
        perror("Errore recv lunghezza della chiave pubblica");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Allocazione memoria per la DH_pubkeyPEM_s proveniente dal server

    // unsigned char *DH_pubkeyPEM_s = malloc((size_t)len + 1);
    unsigned char *DH_pubkeyPEM_s = (unsigned char*)malloc((*len + 1) * sizeof(unsigned char));
    if (!DH_pubkeyPEM_s)
    {
        perror("Errore allocazione memoria per la chiave pubblica");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // RICEVO G^b DAL SERVER

    // bytes_received = recv(sd, DH_pubkeyPEM_s, *len, 0);
    bytes_received = recv(sd, DH_pubkeyPEM_s, *DH_pubkeyLEN_s, 0);

    if (bytes_received < 0)
    {
        perror("Errore recv pubK del server");
        close(sd);
        pthread_exit(NULL);
    }

    printf("Ricevuta la chiave pubblica dal server: \n%s\n", DH_pubkeyPEM_s);

    /////////////////////////
    // INVIO G^a AL SERVER //
    /////////////////////////

    puts("Procedo con la risposta inviando la chiave pubblica del client al server.\n\n");

    uint32_t DHpubkeyLEN = *len;

    // Invia la lunghezza della chiave pubblica al SERVER
    bytes_sent = send(sd, len, sizeof(uint32_t), 0);
    if (bytes_sent < 0)
    {
        perror("Errore send lunghezza della chiave pubblica");
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        close(sd);
        exit(EXIT_FAILURE);
    }

    // INVIO la chiave AL SERVER

    if ((bytes_sent = send(sd, DH_pubkeyPEM_c, *len, 0)) < 0)
    {
        perror("Errore send pubKey al server");
        exit(EXIT_FAILURE);
    }

    // generazione dinamica del file PEM contenente la chiave pubblica del server

    const char *filepath = "ServerPubKey.pem"; // DA CAMBIARE E IMPLEMENTARE L'IMMISSIONE DEL NOME UTENTE
    EVP_PKEY *DHpubKey_s = DH_derive_pubkey(filepath, DH_pubkeyPEM_s, *DH_pubkeyLEN_s);

    if (DHpubKey_s == NULL)
    {
        perror("Errore nella derivazione della chiave pubblica ricevuta dal server\n");
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
    // --- TEST ---
    for (int i = 0; i < *len; i++) {
        printf("%x ", secret[i]);
        //printf("%u ", secret[i]);
        //printf("%c ", secret[i]);
    }
    printf("\n");

    EVP_PKEY_free(DHpubKey_s);
    EVP_PKEY_free(DHprivKey);
    return 0;
}

int main(int argc, char **argv)
{
    int err, sd;
    struct addrinfo hints, *res, *ptr;

    if (argc != 3)
    {
        fprintf(stderr, "Errore argomenti, usa: ./client host porta");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((err = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0)
    {
        fprintf(stderr, "Errore getaddrinfo");
        exit(EXIT_FAILURE);
    }

    for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
        if ((sd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol)) < 0)
        {
            fprintf(stderr, "Errore socket");
            continue;
        }

        if (connect(sd, ptr->ai_addr, ptr->ai_addrlen) == 0)
        {
            puts("Connessione riuscita");
            break;
        }

        close(sd);
    }

    if (ptr == NULL)
    {
        fprintf(stderr, "Errore connessione fallback");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    unsigned char *K_ab = handshake(sd);

    close(sd);
    return 0;
}