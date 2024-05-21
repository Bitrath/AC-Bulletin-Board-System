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
#include "../Utils/rxb.h"
#include "../Utils/utils.h"

void client_control(int sd)
{
    // --- CONTROLLO PRESENZA DELL'UTENTE TRA QUELLI REGISTRATI ---

    char user[MAX_USER_CHAR];
    ssize_t bytes_sent;

    memset(&user, 0, sizeof(user));     // inizializzo tutto il vettore a 0
    size_t user_len = sizeof(user) - 1;

    puts("Inserire il username: ");
    if (fgets(user, sizeof(user), stdin) < 0)
    {
        fprintf(stderr, "Errore fgets user");
        exit(EXIT_FAILURE);
    }
    else if (strlen(user) >= MAX_USER_CHAR - 1) // informati su strnlen
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
       1) SCAMBIO NONCE CON IL CLIENT
       ------------------------------------ */

    unsigned char nonce_c[NONCE_LEN];
    RAND_poll();    // context init
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
        printf("%x ", nonce_s[i]); // %x perche' e' in bytes
    }
    puts("");


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

    signal(SIGCHLD, SIG_IGN);

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