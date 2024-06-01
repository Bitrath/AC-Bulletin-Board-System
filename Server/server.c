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

void safe_exit(int sd)
{
    close(sd);
    printf("*** Client %u Disconnected ***", sd);
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
        safe_exit(ns);
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
   /* 
    (CLIENT HANDSHAKE PROTOCOL) 

    *** (PHASE 1) ***
    *** EPHEMERAL DIFFIE HELLMAN ***
    (SH1): [NONCEs] 
         -> M1 from Client and M2 to Client. 
    (SH2): [Ephemeral DIFFIE-HELLMAN Setup] 
         -> <Server DH {PU, PR}> generation
    (SH3): [DH PubKey Exchange]
         A) M3 and M4 send to Client. {s_DH_PUk_len, s_DH_PUk}
         B) M5 and M6 from Client. {c_DH_PUk_len, c_DH_PUk}
    (SH4): [DH Shared Secret]
         -> Diffie-Hellman Shared Secret Derivation.
    (SH5): [Session Key Kab]
         -> Session Key {Kab} Derivation.

    *** (PHASE 2) ***
    *** SERVER RSA VERIFIICATION ***

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

    printf("\n--- SERVER HANDSHAKE (%u)----\n", ns);

    //*** (PHASE 1) ***
    //*** EPHEMERAL DIFFIE HELLMAN ***

    // --> STEP (SH1)
    // (SH1): NONCE Exchange 

    uint32_t *len;
    
    // (SH1): Client -> M1{nonce_c}
    unsigned char *nonce_c = (unsigned char *)malloc(NONCE_LEN);
    ssize_t bytes_received = recv(ns, nonce_c, NONCE_LEN, 0);
    if (bytes_received < 0)
    {
        perror("SERVER Error: client_nonce_recv() failure.\n");
        safe_exit(ns);
    }
    
    printf("(SH1): <Client Nonce> received.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_c[i]); // %x perche' e' in bytes
    }

    // Server Nonce
    unsigned char *nonce_s = (unsigned char *)malloc(NONCE_LEN);
    RAND_poll();                                  
    int rs = RAND_bytes(nonce_s, NONCE_LEN);
    if (rs != 1)
    {
        perror("SERVER Error: server_nonce_creation() failure.\n");
        free(nonce_c);
        safe_exit(ns);
    }

    printf("\n(SH1): <Server Nonce> created.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++)
    {
        printf("%x ", nonce_s[i]);
    }

    // (SH1): Client <- M2{nonce_s}
    ssize_t bytes_sent = send(ns, nonce_s, NONCE_LEN, 0);
    if (bytes_sent < 0)
    {
        perror("SERVER Error: server_nonce_send() failure.\n");
        free(nonce_c);
        safe_exit(ns);
    }

    // --> STEP (SH2)
    // (SH2): Ephemeral DIFFIE-HELLMAN Server Setup

    // Server DH_Priv_Key
    EVP_PKEY *DHprivKey = DH_privkey();

    // Server DH_Priv_Key length: memory allocation
    len = (uint32_t *)malloc(sizeof(uint32_t));
    if (!len)
    {
        perror("SERVER Error: server_len_malloc() failure.\n");
        free(nonce_c);
        free(nonce_s);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }

    // Server DH_Puk_Key
    unsigned char *DH_pubkeyPEM_s = DH_pub_key("dh_PUBKEY_server.pem", DHprivKey, len);
    if (!DH_pubkeyPEM_s)
    {
        perror("SERVER Error: (SH2) PKs_PEM_read() failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }
    printf("(SH2): <Server Public Key> created.\n-> %s", DH_pubkeyPEM_s);

    // Server DH_Priv_Key length
    uint32_t DHpubkeyLEN = *len;

    // --> STEP (SH3)
    // (SH3): DH Keys Exchange

    // (SH3): Client <- M3{s_DH_PUk_len}
    bytes_sent = send(ns, len, sizeof(uint32_t), 0);
    if (bytes_sent < 0)
    {
        perror("SERVER Error: PKs_len_send() failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }

    // (SH3): Client <- M4{s_DH_PUk} [G^b]
    if ((bytes_sent = send(ns, DH_pubkeyPEM_s, DHpubkeyLEN, 0)) < 0)
    {
        perror("SERVER Error: PKs_send() failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }
    puts("(SH2): <Server Public Key> to <Client>.");

    // (SH3): Client -> M5{c_DH_PUk_len}
    uint32_t *DH_pubkeyLEN_c = (uint32_t *)malloc(sizeof(uint32_t));
    bytes_received = recv(ns, DH_pubkeyLEN_c, sizeof(uint32_t), 0);
    if (bytes_received <= 0)
    {
        perror("SERVER Error: cPuK_len_rec() failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }

    /*
    unsigned char *DH_pubkeyPEM_c = malloc((size_t)len + 1);
    unsigned char *DH_pubkeyPEM_c = (unsigned char *)malloc((*len + 1) * sizeof(unsigned char));
    */
    
    // Client DH_Pub_Key: memory allocation
    unsigned char *DH_pubkeyPEM_c = (unsigned char *)malloc(*DH_pubkeyLEN_c);
    if (!DH_pubkeyPEM_c)
    {
        perror("SERVER Error: cPuK_malloc() failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        free(DH_pubkeyLEN_c);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }

    // (SH3): Client -> M6{c_DH_PUk} [G^a]
    bytes_received = recv(ns, DH_pubkeyPEM_c, *DH_pubkeyLEN_c, 0);
    if (bytes_received < 0)
    {
        perror("SERVER Error: cPuK_recv() failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        free(DH_pubkeyLEN_c);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }
    printf("(SH3): <Client Public Key> received.\n-> %s", DH_pubkeyPEM_c);

    // (Client_DH_Pub_Key).PEM
    const char *filepath = "ClientPubKey.pem";
    EVP_PKEY *DHpubKey_c = DH_derive_pubkey(filepath, DH_pubkeyPEM_c, *DH_pubkeyLEN_c);
    if (DHpubKey_c == NULL)
    {
        perror("SERVER Error: PuK_derivation() failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        free(DH_pubkeyLEN_c);
        free(DH_pubkeyPEM_c);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }

    // --> STEP (SH4)
    // (SH4): Diffie-Hellman Shared Secret Derivation.

    // To retrieve the shared secret's length after the DH_derive_shared_secret call
    size_t shared_secret_len;

    // Server Shared Secret
    unsigned char *secret = DH_derive_shared_secret(DHprivKey, DHpubKey_c, &shared_secret_len);
    if (!secret)
    {
        perror("SERVER Error: shared_secret_creation() failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        free(DH_pubkeyLEN_c);
        free(DH_pubkeyPEM_c);
        EVP_PKEY_free(DHprivKey);
        EVP_PKEY_free(DHpubKey_c);
        safe_exit(ns);
    }
    printf("(SH4): <Server Secret>\n-> %hhu \n", *secret);

    // --> STEP (SH5)
    // (SH5): Session Key {Kab} derivation

    // Server Session Key {Kab}
    // @param {k_len} comes as an argument of the handshake function
    unsigned char *session_key = create_session_key(EVP_sha256(), EVP_aes_128_gcm(), secret, shared_secret_len, k_len);
    if (!session_key)
    {
        perror("SERVER Error: create_session_key (failure).\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        free(DH_pubkeyLEN_c);
        free(DH_pubkeyPEM_c);
        free(secret);
        EVP_PKEY_free(DHprivKey);
        EVP_PKEY_free(DHpubKey_c);
        safe_exit(ns);
    }
    printf("(SH5): <Server Session Key>\n-> %hhu\n", *session_key);

    // Memory Cleaning
    free(len);
    free(DH_pubkeyPEM_s);
    free(DH_pubkeyLEN_c);
    free(DH_pubkeyPEM_c);
    free(secret);
    EVP_PKEY_free(DHprivKey);
    EVP_PKEY_free(DHpubKey_c);

    // *** END (PHASE 1) ***

    // *** BEGIN (PHASE 2) ***

    printf("--- END SERVER HANDSHAKE (%u) ---\n", ns);

    return session_key; 
}

void *secureConnection(void *old_sd)
{
    char *user = "";
    int sd = *((int *)old_sd);
    unsigned int key_len = 0;

    unsigned char *K_ab = handshake(sd, &key_len, user);

    safe_exit(sd);
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

/*
    Client  |||  Server
    
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