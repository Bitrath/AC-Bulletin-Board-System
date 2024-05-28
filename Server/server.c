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
    puts("\n-----(Client Disconnected)-----\n");
    pthread_exit(NULL);
}

int client_control(int ns) // ritorna 1 se il client e' effettivamente presente nel DB
{
    // --- RICEZIONE DEL NOME UTENTE DA CONTROLLARE TRA QUELLI REGISTRATI ---

    char user[MAX_USER_CHAR];
    ssize_t bytes_rcv = recv(ns, user, sizeof(user), 0);

    if (bytes_rcv < 0)
    {
        perror("SERVER Error: client_control() -> recv() failure.\n");
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
    printf("\nUsername: ");
    for (size_t i = 0; i < user_len; ++i)
    {
        printf("%c", user[i]);
    }
    puts("");

    int result = system(command); // Esecuzione del comando e controllo del valore di ritorno
                                  // per vedere se l'user e' stato trovato

    if (result == 0)
    {
        puts("\nServer: <Client Username> in <Server List>. Login...");
        return 1;
    }
    else if (result == 256)
    {
        puts("\nServer: <Client Username> not in <Server List>. Not registered.");
        t_disconnect(ns);
        return 0;
    }
    else
    {
        printf("SERVER Error: client_control() -> grep() failure.\n");
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
        perror("SERVER Error: handshake() -> recv() failure.\n");
        close(ns);
        pthread_exit(NULL);
    }

    printf("\nServer: <Client Nonce> received.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_c[i]); // %x perche' e' in bytes
    }
    puts("");

    // --- CREAZIONE NONCE SERVER ---

    unsigned char nonce_s[NONCE_LEN];
    RAND_poll();                                   // context init
    int rs = RAND_bytes(nonce_s, sizeof(nonce_s)); // nonce del client creato con successo

    if (rs != 1)
    {
        fprintf(stderr, "SERVER Error: handhake() -> Server NONCE generation failure.\n");
        exit(EXIT_FAILURE);
    }

    printf("\nServer: <Server Nonce> cretaion successful.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_s[i]);
    }

    // --- INVIO DEL NONCE SERVER AL CLIENT ---

    puts("\n\nServer: Sending <Server Nonce> to <Client>...");

    ssize_t bytes_sent = send(ns, nonce_s, sizeof(nonce_s), 0); // con la rxb non si riesce perchè comunica solo in char
                                                                // piu' comode la send e rcv
    if (bytes_sent < 0)
    {
        perror("SERVER Error: handhake() -> Server NONCE send() to Client failure.\n");
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
        perror("SERVER Error: handhake() -> malloc() failure.\n");
        EVP_PKEY_free(DHprivKey);
        free(len);
        t_disconnect(ns);
    }
    // Get the (string) Server_Pub_Key from Server.PEM file
    unsigned char *DH_pubkeyPEM_s = DH_pub_key("dh_PUBKEY_server.pem", DHprivKey, len);

    if (!DH_pubkeyPEM_s)
    {
        perror("SERVER Error: handhake() -> pubKey.pem file READ failure.\n");
        EVP_PKEY_free(DHprivKey);
        free(len);
        t_disconnect(ns);
    }

    printf("\nServer: <Server Public Key> success.\n-> %s\n", DH_pubkeyPEM_s);

    uint32_t DHpubkeyLEN = *len;
    // EVP_PKEY_free(DHpubKey); ---> inutile ??

    // Invia la lunghezza della chiave pubblica al CLIENT
    bytes_sent = send(ns, len, sizeof(uint32_t), 0);
    if (bytes_sent < 0)
    {
        perror("SERVER Error: handhake() -> pubKey_server length send() failure.\n");
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        close(ns);
        exit(EXIT_FAILURE);
    }

    // INVIO G^b AL CLIENT

    if ((bytes_sent = send(ns, DH_pubkeyPEM_s, DHpubkeyLEN, 0)) < 0)
    {
        perror("SERVER Error: handhake() -> pubKey_server send() failure.\n");
        exit(EXIT_FAILURE);
    }

    puts("\nServer: <Server Public Key> to <Client> success.\n");

    ///////////////////////////
    // RICEVO G^a DAL CLIENT //
    ///////////////////////////

    // Ricezione della lunghezza della chiave pubblica del server

    uint32_t *DH_pubkeyLEN_c = (uint32_t *)malloc(sizeof(uint32_t));

    bytes_received = recv(ns, DH_pubkeyLEN_c, sizeof(uint32_t), 0);
    if (bytes_received <= 0)
    {
        perror("SERVER Error: handhake() -> pubKey_client recv() lenght failure.\n");
        close(ns);
        exit(EXIT_FAILURE);
    }

    // Allocazione memoria per la DH_pubkeyPEM_s proveniente dal server

    unsigned char *DH_pubkeyPEM_c = malloc((size_t)len + 1);
    if (!DH_pubkeyPEM_c)
    {
        perror("SERVER Error: handhake() -> pubKey memory allocation failure.\n");
        close(ns);
        exit(EXIT_FAILURE);
    }

    // RICEVO G^b DAL SERVER

    bytes_received = recv(ns, DH_pubkeyPEM_c, *len, 0);

    if (bytes_received < 0)
    {
        perror("SERVER Error: handhake() -> Server pubKey recv() failure.\n");
        close(ns);
        pthread_exit(NULL);
    }

    printf("\nServer: <Client Public Key> received.\n-> %s\n", DH_pubkeyPEM_c);

    // generazione dinamica del file PEM contenente la chiave pubblica del client

    const char *filepath = "ClientPubKey.pem";
    EVP_PKEY *DHpubKey_c = DH_derive_pubkey(filepath, DH_pubkeyPEM_c, *DH_pubkeyLEN_c);

    if (DHpubKey_c == NULL)
    {
        perror("SERVER Error: handshake() -> Failure to extract client public key.");
        EVP_PKEY_free(DHprivKey);
        free(DH_pubkeyPEM_s);
        free(DH_pubkeyLEN_c);
        free(DH_pubkeyPEM_c);

        t_disconnect(ns);
    }

    ////////////////////////////////////////
    /// Derivo la chiave di sessione Kab ///
    ////////////////////////////////////////

    // To retrieve the shared secret’s length after the DH_derive_shared_secret call
    size_t session_key_len;

    // derivation of the shared secret
    unsigned char *secret = DH_derive_shared_secret(DHprivKey, DHpubKey_c, &session_key_len);
    //puts(secret);

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
    int sd, err, pid, status, on, *ns = (int *)malloc(sizeof(int));
    struct addrinfo hints, *res;
    struct sigaction sa;
    pthread_t t_id;

    if (argc != 2)
    {
        fprintf(stderr, "\nSERVER Error: too many arguments, write as: ./server port");
        exit(EXIT_FAILURE);
    }

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = handler;

    if (sigaction(SIGCHLD, &sa, NULL) == -1)
    {
        perror("\nSERVER Error: main() -> sigaction() failure");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((err = getaddrinfo(NULL, argv[1], &hints, &res)) != 0)
    {
        perror("\nSERVER Error: main() -> getaddrinfo() failure");
        exit(EXIT_FAILURE);
    }

    if ((sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
    {
        perror("\nSERVER Error: main() -> socket() failure.");
        exit(EXIT_FAILURE);
    }

    on = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
    {
        perror("\nSERVER Error: main() -> setsockopt() failure.");
        exit(EXIT_FAILURE);
    }

    if (bind(sd, res->ai_addr, res->ai_addrlen) < 0)
    {
        perror("\nSERVER Error: main() -> bind() failure.");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    if (listen(sd, SOMAXCONN) < 0)
    {
        perror("\nSERVER Error: main() -> listen() failure.");
        exit(EXIT_FAILURE);
    }

    for (;;)
    {
        puts("\nServer: listening for <Client>...");

        if ((*ns = accept(sd, NULL, NULL)) < 0)
        {
            perror("\nSERVER Error: main() -> accept() failure.");
            exit(EXIT_FAILURE);
        }

        if (pthread_create(&t_id, NULL, secureConnection, (void *)ns))
        { // crea un nuovo thread che gestisce il socket client-server
            puts("\nSERVER Error: main() -> pthread_create() failure.");
            close(*ns);
            close(sd);
            free(ns);
        }
        pthread_detach(t_id);
    }
    close(sd);
    return 0;
}