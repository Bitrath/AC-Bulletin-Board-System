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
#include "../Utils/Dif_Hel.h"
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
        puts("Utente presente, login in corso...");
        return 1;
    }
    else if (result == 256)
    {
        puts("L'utente attuale non e' registrato.");
        t_disconnect(ns);
        return 0;
    }
    else
    {
        printf("Errore durante l'esecuzione di grep.\n");
        return 0;
    }
}

unsigned char *handshake(int ns, unsigned int *k_len, char *name) // name opzionale (da usare solo se si effettua il login)
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

    /* --------------------------------
       1) SCAMBIO NONCE CON IL CLIENT
       -------------------------------- */

    // --- RICEZIONE DEL NONCE DAL CLIENT ---

    unsigned char nonce_c[NONCE_LEN];
    uint32_t *len;
    ssize_t bytes_received = recv(ns, nonce_c, sizeof(nonce_c), 0);
    if (bytes_received < 0)
    {
        perror("SERVER Error: (SH1) client_nonce_recv() failure.\n");
        close(ns);
        pthread_exit(NULL);
    }
    printf("\n--- SERVER HANDSHAKE (%u)----\n", ns);
    printf("(SH1): <Client Nonce> received.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_c[i]); // %x perche' e' in bytes
    }

    // --- CREAZIONE NONCE SERVER ---

    unsigned char nonce_s[NONCE_LEN];
    RAND_poll();                                   // context init
    int rs = RAND_bytes(nonce_s, sizeof(nonce_s)); // nonce del client creato con successo
    if (rs != 1)
    {
        fprintf(stderr, "SERVER Error: (SH1) server_nonce_creation() failure.\n");
        exit(EXIT_FAILURE);
    }

    printf("\n(SH1): <Server Nonce> created.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_s[i]);
    }

    // --- INVIO DEL NONCE SERVER AL CLIENT ---

    puts("\n(SH1): <Server Nonce> to <Client>.");

    ssize_t bytes_sent = send(ns, nonce_s, sizeof(nonce_s), 0); // con la rxb non si riesce perchè comunica solo in char
                                                                // piu' comode la send e rcv
    if (bytes_sent < 0)
    {
        perror("SERVER Error: (SH1) server_nonce_send() failure.\n");
        exit(EXIT_FAILURE);
    }

    /* ------------------------------------
       2) CREAZIONE CHIAVE PRIVATA E PUBBLICA
       ------------------------------------ */

    // --- CREAZIONE CHIAVE PRIVATA SERVER ---

    EVP_PKEY *DHprivKey = DH_privkey();

    // --- INIZIALIZZAZIONE STRUCT PER LA CHIAVE PUBBLICA

    // EVP_PKEY *DHpubKey = EVP_PKEY_new(); ---> potenzialmente inutile

    // ricavo e leggo file PEM con la mia chiave pubblica
    // genera dinamicamente il nome del file!

    len = (uint32_t *)malloc(sizeof(uint32_t));
    if (!len)
    {
        perror("SERVER Error: (SH2) server_len_malloc() failure.\n");
        EVP_PKEY_free(DHprivKey);
        free(len);
        t_disconnect(ns);
    }
    // Get the (string) Server_Pub_Key from Server.PEM file
    unsigned char *DH_pubkeyPEM_s = DH_pub_key("dh_PUBKEY_server.pem", DHprivKey, len);
    if (!DH_pubkeyPEM_s)
    {
        perror("SERVER Error: (SH2) PKs_PEM_read() failure.\n");
        EVP_PKEY_free(DHprivKey);
        free(len);
        t_disconnect(ns);
    }

    printf("(SH2): <Server Public Key> created.\n-> %s", DH_pubkeyPEM_s);

    uint32_t DHpubkeyLEN = *len;

    // Invia la lunghezza della chiave pubblica al CLIENT
    bytes_sent = send(ns, len, sizeof(uint32_t), 0);
    if (bytes_sent < 0)
    {
        perror("SERVER Error: (SH2) PKs_len_send() failure.\n");
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        close(ns);
        exit(EXIT_FAILURE);
    }

    // INVIO G^b AL CLIENT

    if ((bytes_sent = send(ns, DH_pubkeyPEM_s, DHpubkeyLEN, 0)) < 0)
    {
        perror("SERVER Error: (SH2) PKs_send() failure.\n");
        exit(EXIT_FAILURE);
    }

    puts("(SH2): <Server Public Key> to <Client>.");

    /* ------------------------------------
       3) Chiave Pubblica da Client
       ------------------------------------ */
    ///////////////////////////
    // RICEVO G^a DAL CLIENT //
    ///////////////////////////

    // Ricezione della lunghezza della chiave pubblica del server

    uint32_t *DH_pubkeyLEN_c = (uint32_t *)malloc(sizeof(uint32_t));

    bytes_received = recv(ns, DH_pubkeyLEN_c, sizeof(uint32_t), 0);
    if (bytes_received <= 0)
    {
        perror("SERVER Error: (SH3) cPuK_len_rec() failure.\n");
        close(ns);
        exit(EXIT_FAILURE);
    }

    // Allocazione memoria per la DH_pubkeyPEM_s proveniente dal server

    // unsigned char *DH_pubkeyPEM_c = malloc((size_t)len + 1);
    //unsigned char *DH_pubkeyPEM_c = (unsigned char *)malloc((*len + 1) * sizeof(unsigned char));
    unsigned char *DH_pubkeyPEM_c = (unsigned char *)malloc(*len);
    if (!DH_pubkeyPEM_c)
    {
        perror("SERVER Error: (SH3) cPuK_malloc() failure.\n");
        close(ns);
        exit(EXIT_FAILURE);
    }

    // RICEVO G^b DAL CLIENT

    // bytes_received = recv(ns, DH_pubkeyPEM_c, *len, 0);
    bytes_received = recv(ns, DH_pubkeyPEM_c, *DH_pubkeyLEN_c, 0);
    if (bytes_received < 0)
    {
        perror("SERVER Error: (SH3) cPuK_recv() failure.\n");
        close(ns);
        pthread_exit(NULL);
    }

    printf("(SH3): <Client Public Key> received.\n-> %s", DH_pubkeyPEM_c);

    // generazione dinamica del file PEM contenente la chiave pubblica del client

    const char *filepath = "ClientPubKey.pem";
    EVP_PKEY *DHpubKey_c = DH_derive_pubkey(filepath, DH_pubkeyPEM_c, *DH_pubkeyLEN_c);
    if (DHpubKey_c == NULL)
    {
        perror("SERVER Error: (SH3) cPuK_derivation() failure.\n");
        EVP_PKEY_free(DHprivKey);
        free(DH_pubkeyPEM_s);
        free(DH_pubkeyLEN_c);
        free(DH_pubkeyPEM_c);

        t_disconnect(ns);
    }

    ////////////////////////////////////////
    /// 4) Derivo la chiave di sessione Kab ///
    ////////////////////////////////////////

    // To retrieve the shared secret’s length after the DH_derive_shared_secret call
    size_t session_key_len;

    // derivation of the shared secret
    unsigned char *secret = DH_derive_shared_secret(DHprivKey, DHpubKey_c, &session_key_len);
    //puts(secret); // --- TEST ---printf("\nServer: <Server Secret>: ");
    printf("(SH4): <Server Secret>\n-> %hhu ", *secret);
    for (int i = 0; i < *len; i++) {
        //printf("%x ", secret[i]);
        //printf("%u ", secret[i]);
        //printf("%c ", secret[i]);
    }

    EVP_PKEY_free(DHpubKey_c);
    EVP_PKEY_free(DHprivKey);

    printf("--- END SERVER HANDSHAKE (%u)----\n", ns);

    return secret; // TEMPORANEO
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
    int sd, err, on, *ns = (int *)malloc(sizeof(int));
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