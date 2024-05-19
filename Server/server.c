#define _POSIX_C_SOURCE 200809L
#define MAX_USER_CHAR 128
#define MAX_REQUEST_SIZE (64 * 1024)
#define NONCE_LEN 16
#define COMMAND_DIM 100
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "../Utils/utils.h"
#include "../Utils/rxb.h"

void handler(int signo)
{
    int status;
    (void)signo;

    while (waitpid(-1, &status, WNOHANG) > 0)
        continue;
}

void t_disconnect(int sd)
{
    close(sd);
    puts("Client Disconnected.");
    pthread_exit(NULL);
}

int client_control(int ns) // ritorna 1 se il client e' effettivamente presente nel DB
{
    // --- RICEZIONE DEL NOME UTENTE DA CONTROLLARE TRA QUELLI REGISTRATI ---

    char user[MAX_USER_CHAR];
    ssize_t bytes_rcv = recv(ns, user, sizeof(user), 0);

    if (bytes_rcv < 0)
    {
        perror("Errore recv");
        close(ns);
        pthread_exit(NULL);
    }

    int user_len = strlen(user);
    user[user_len - 1] = '\0'; // aggiungo il char terminatore al posto dell'invio 

    // [(N), (i), (c), (o), ..., (\0))

    // --- CONTROLLO EFFETTIVO SUL FILE utenti.txt ---

    char command[COMMAND_DIM];
    sprintf(command, "grep -qw '%s' utenti.txt", user); // grep silenziosa (senza output con -q)
                                                        // e con solo parole cercate intere (-w)
                                                        // gli '' servono per confermare una
                                                        // corrispondenza esatta
    printf("Nome utente: ");
    for (size_t i = 0; i < user_len; ++i)
    {
        printf("%c", user[i]);
    }
    puts("");

    int result = system(command); // Esecuzione del comando e controllo del valore di ritorno
                                  // per vedere se l'user e' stato trovato

    if (result == 0)
    {
        printf("Utente presente, login in corso...\n");
        return 1;
    }
    else if (result == 256)
    {
        printf("L'utente attuale non e' registrato.\n");
        t_disconnect(ns);
        return 0;
    }
    else
    {
        printf("Errore durante l'esecuzione di grep.\n");
        return 0;
    }
}

void *handshake(int ns, unsigned int *k_len, char *name)    // name opzionale (da usare solo se si effettua il login)
{
    /* handshake -> funzione che si occupa dello scambio di dati tra client e server
                    al fine di effettuare l'autenticazione del client e di stabilire
                    una chiave di sessione, creare certificati, ecc...
                    Porta come argomenti la:
                        - ns -> effettiva socket per scambiare dati
                        - k_len -> lunghezza della chiave
                        - name -> nome dell'utente client

                    Questa funzione returnera' la chiave di sessione (segreto condiviso)
    */

    /* ------------------------------------
       1) SCAMBIO NONCE CON IL CLIENT
       ------------------------------------ */

    // --- RICEZIONE DEL NONCE DAL CLIENT ---

    unsigned char nonce_c[NONCE_LEN];
    ssize_t bytes_received = recv(ns, nonce_c, sizeof(nonce_c), 0);

    if (bytes_received < 0)
    {
        perror("Errore recv");
        close(ns);
        pthread_exit(NULL);
    }

    printf("Nonce del client ricevuto: ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_c[i]); // %x perche' e' in bytes
    }
    puts("");

    // --- CREAZIONE NONCE SERVER ---

    unsigned char nonce_s[NONCE_LEN];
    int rs = RAND_bytes(nonce_s, sizeof(nonce_s)); // nonce del client creato con successo
    if (rs != 1)
    {
        fprintf(stderr, "Errore creazione nonce");
        exit(EXIT_FAILURE);
    }

    printf("Calcolato il nonce server: ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_s[i]);
    }

    // --- INVIO DEL NONCE SERVER AL CLIENT ---

    puts("\nInvio il nonce del client al server...");

    ssize_t bytes_sent = send(ns, nonce_s, sizeof(nonce_s), 0); // con la rxb non si riesce perchè comunica solo in char
                                                                // piu' comode la send e rcv
    if (bytes_sent < 0)
    {
        perror("Errore send nonce al client");
        exit(EXIT_FAILURE);
    }
    

    return 0;
}

void *secureConnection(void *old_sd)
{
    char *user = "";
    int sd = *((int *)old_sd);
    unsigned int key_len = 0;

    unsigned char *K_ab = handshake(sd, &key_len, user);

    t_disconnect(sd);

    return 0;
}

int main(int argc, char **argv)
{
    int sd, err, pid, status, on, *ns = (int *)malloc(sizeof(int));
    struct addrinfo hints, *res;
    struct sigaction sa;
    pthread_t t_id;

    if (argc != 2)
    {
        fprintf(stderr, "Errore argomenti, usa: ./server porta");
        exit(EXIT_FAILURE);
    }

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = handler;

    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("Errore sigaction");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((err = getaddrinfo(NULL, argv[1], &hints, &res)) != 0)
    {
        perror("Errore getaddrinfo");
        exit(EXIT_FAILURE);
    }

    if ((sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
    {
        perror("Errore socket");
        exit(EXIT_FAILURE);
    }

    on = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    {
        perror("Errore setsockopt");
        exit(EXIT_FAILURE);
    }

    if (bind(sd, res->ai_addr, res->ai_addrlen) < 0)
    {
        perror("Errore bind");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    if (listen(sd, SOMAXCONN) < 0)
    {
        perror("Errore listen");
        exit(EXIT_FAILURE);
    }

    for (;;)
    {
        puts("Server in ascolto...");

        if ((*ns = accept(sd, NULL, NULL)) < 0)
        {
            perror("Errore accept");
            exit(EXIT_FAILURE);
        }

        if (pthread_create(&t_id, NULL, secureConnection, (void *)ns))
        { // crea un nuovo thread che gestisce il socket client-server
            puts("Errore creazione del thread");
            close(*ns);
            close(sd);
            free(ns);
        }
        pthread_detach(t_id);
    }
    close(sd);
    return 0;
}