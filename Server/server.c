#define _POSIX_C_SOURCE 200809L
#define MAX_USER_CHAR 32
#define MAX_PW_CHAR 32
#define MAX_REQUEST_SIZE (64 * 1024)
#define NONCE_LEN 16
#define COMMAND_DIM 100
#define MAX_RESULT_CHAR 16
#define CIPHER_LENGTH 128
#define IV_LENGTH 16
#include <time.h>
#include <math.h>
#include <stdio.h>
#include <stdbool.h>
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
#include "../Utils/utils.h"
#include "../Utils/rxb.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "../Utils/Dif_Hel.h"
#include "../Utils/digital_signature.h"
#include "../Utils/Enc_Dec.h"

// Funzione per stampare i dati in formato esadecimale
void print_hex(const unsigned char *data, size_t len)
{
    puts("Cipher ricevuto:");
    for (size_t i = 0; i < len; i++)
    {
        printf("%02x ", data[i]);
    }
    printf("\n");
    printf("Lunghezza cipher: %zu\n", len);
}

// Funzione per stampare una stringa con spazi visibili
void print_str_with_spaces(const char *title, const char *str, size_t len)
{
    printf("%s: '", title);
    for (size_t i = 0; i < len; i++)
    {
        if (str[i] == '\0')
            printf("\\0");
        else
            printf("%c", str[i]);
    }
    printf("'\n");
}

typedef struct ACCOUNT
{
    char email[MAX_USER_CHAR];
    char username[MAX_USER_CHAR];
    char password[MAX_PW_CHAR];

} ACCOUNT;

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

int client_control(int ns, unsigned char *user, unsigned char *K_ab) // ritorna 1 se il client e' effettivamente presente nel DB
{
    // --- RICEZIONE DEL NOME UTENTE DA CONTROLLARE TRA QUELLI REGISTRATI ---

    unsigned char cipher_user[IV_LENGTH + CIPHER_LENGTH];
    ssize_t bytes_received = recv(ns, cipher_user, sizeof(cipher_user), 0);
    unsigned char iv[IV_LENGTH];

    if (bytes_received <= 0)
    {
        perror("Errore recv");
        close(ns);
        pthread_exit(NULL);
    }

    // Copia l'IV dai primi 'iv_len' byte del buffer ricevuto
    memcpy(iv, cipher_user, IV_LENGTH);

    // Calcola la lunghezza effettiva del ciphertext
    size_t ciphertext_len = bytes_received - IV_LENGTH;

    // Copia il ciphertext dal buffer (partendo dal byte 'iv_len' fino alla fine)
    memcpy(cipher_user, cipher_user + IV_LENGTH, ciphertext_len);

    int user_len = decrypt_data(cipher_user, ciphertext_len, K_ab, iv, user);

    // Verifica la lunghezza del testo decriptato
    if (user_len < 0)
    {
        fprintf(stderr, "Errore nella decrittazione dei dati.\n");
        close(ns);
        pthread_exit(NULL);
    }

    user[user_len] = '\0';
    print_hex(user, ciphertext_len);
    printf("User ricevuto: %s\n", (char *)user);

    // --- CONTROLLO EFFETTIVO SUL FILE utenti.txt ---

    char command[COMMAND_DIM];
    sprintf(command, "grep -qw '%s' utenti.txt", user); // grep silenziosa (senza output con -q)
                                                        // e con solo parole cercate intere (-w)
                                                        // gli '' servono per confermare una
                                                        // corrispondenza esatta

    int result = system(command); // Esecuzione del comando e controllo del valore di ritorno
                                  // per vedere se l'user e' stato trovato

    if (result == 0)
    {
        puts("Utente presente, login in corso...");
        return 1;
    }
    else if (result == 256)
    {
        puts("L'utente non e' registrato.");
        return 0;
    }
    else
    {
        puts("Errore durante la ricerca nel database del nome utente.");
        return -1;
    }
}

int login(char *user, char *pw) // ritorna 1 se l'utente ha effettuato il login con successo
{
    // il nome utente lo abbiamo gia' dal client_control

    // dobbiamo ricevere la password cifrata
    return 0;
}

unsigned char *handshake(int ns, unsigned int *k_len, char *name)
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
     *** SERVER RSA AUTHENTICATION ***
     (S_RSA1): The server creates a proof by signing a message M (which could include the session key or a nonce) with its private RSA key.
         -> M7: M = {nonce_c||s_DH_PUk}. Y = M7 = E{ M, Server_PrivKey_RSA }
     (S_RSA2): The server sends the signed message M7 to the client.

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

    /* (For now we don't clean memory, let's see what the other steps need.)
    // Memory Cleaning
    free(len);
    free(DH_pubkeyPEM_s);
    free(DH_pubkeyLEN_c);
    free(DH_pubkeyPEM_c);
    free(secret);
    EVP_PKEY_free(DHprivKey);
    EVP_PKEY_free(DHpubKey_c);
    */
    // *** END (PHASE 1) ***

    // *** BEGIN (PHASE 2) ***
    // *** Server Authentication ***
    // (S_RSA1): The server creates a proof by signing a message M (which could include the session key or a nonce) with its private RSA key.
    //   -> M7: M = {nonce_c||s_DH_PUk}. Y = M7 = E{ M, Server_PrivKey_RSA }
    // (S_RSA2): The server sends the signed message M7 to the client.

    // --> STEP (S_RSA1)
    // (S_RSA1): The server creates a proof by signing a message M (which could include the session key or a nonce) with its private RSA key.

    const char *server_privkey_rsa_filepath = "Server-Wallet/server_privkey_rsa.pem";

    // Server RSA_Priv_Key
    EVP_PKEY *server_privkey_rsa = Private_RSA_Key_From_File(server_privkey_rsa_filepath);
    if (!server_privkey_rsa)
    {
        perror("SERVER Error: RSA Private Key read failure.\n");
        safe_exit(ns);
    }

    // Server RSA_Message length: memory allocation
    uint32_t *server_rsa_message_length = (uint32_t *)malloc(sizeof(uint32_t));
    if (!server_rsa_message_length)
    {
        perror("SERVER Error: RSA Message length allocation failure.\n");
        safe_exit(ns);
    }

    // Server RSA plaintext message
    // X = {nonce_c || s_DH_PubKey}
    unsigned char *server_message_rsa = (unsigned char *)malloc(NONCE_LEN + DHpubkeyLEN);
    if (!server_message_rsa)
    {
        perror("SERVER Error: RSA Message length allocation failure.\n");
        free(server_rsa_message_length);
        safe_exit(ns);
    }
    // X = { 0 -> nonce_c -> 15 || ... }
    memcpy(server_message_rsa, nonce_c, NONCE_LEN);
    // X = { 0 -> nonce_c -> 15 || 15 -> server_DH_pubkey -> DHpubkeyLEN - 1 }
    memcpy(server_message_rsa + NONCE_LEN, DH_pubkeyPEM_s, *len);

    size_t message_len = (size_t)(NONCE_LEN + *len); // this works

    // printf("\n(TEST M): <nonce_c + dh_s_pk>\n-> %hhu\n", *server_message_rsa);

    // Server RSA+SHA256 ciphertext signature
    unsigned char *server_signature = SignatureWithRSA(EVP_sha256(), server_message_rsa, message_len, server_privkey_rsa, server_rsa_message_length);
    if (!server_signature)
    {
        perror("SERVER Error: RSA signature failure.\n");
        free(server_rsa_message_length);
        free(server_message_rsa);
        safe_exit(ns);
    }

    printf("(S_RSA1): <Server Signature>\n-> ");

    for (int i = 0; i < *server_rsa_message_length; i++)
    {
        printf("%x ", server_signature[i]);
    }

    // --> STEP (S_RSA2)
    // (S_RSA1): Send M7 (signature_length) and M7 (signature) to Client

    // Send M7: signature length
    bytes_sent = send(ns, server_rsa_message_length, sizeof(uint32_t), 0);

    if (bytes_sent < 0)
    {
        perror("SERVER Error: RSA signature_length send failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }

    uint32_t server_sig_length = *server_rsa_message_length;

    // Send M8: rsa signature
    // M8: M = {nonce_c||s_DH_PUk}. Y = M7 = E{H(M), Server_PrivKey_RSA}
    bytes_sent = send(ns, server_signature, server_sig_length, 0);

    if (bytes_sent < 0)
    {
        perror("SERVER Error: RSA signature send failure.\n");
        free(nonce_c);
        free(nonce_s);
        free(len);
        free(DH_pubkeyPEM_s);
        EVP_PKEY_free(DHprivKey);
        safe_exit(ns);
    }
    printf("\n(S_RSA2): <Server RSA + SHA256 Signature> to <Client>.\n\n");
    printf("SIZES: signature(%u) test_message(%zu)\n", server_sig_length, message_len);

    printf("\n--- END SERVER HANDSHAKE (%u) ---\n", ns);

    return session_key;
}

void registration(int sd, char *email, char *user, char *pw, unsigned char *K_ab)
{
    unsigned char cipher_email[CIPHER_LENGTH + IV_LENGTH];
    unsigned char iv[IV_LENGTH];

    ssize_t bytes_received = recv(sd, cipher_email, sizeof(cipher_email), 0);

    if (bytes_received < 0)
    {
        perror("SERVER error: Failed to get the encrypted email from the client.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Copia l'IV dai primi 'iv_len' byte del buffer ricevuto
    memcpy(iv, cipher_email, IV_LENGTH);

    // Calcola la lunghezza effettiva del ciphertext
    size_t ciphertext_len = bytes_received - IV_LENGTH;

    // Copia il ciphertext dal buffer (partendo dal byte 'iv_len' fino alla fine)
    memcpy(cipher_email, cipher_email + IV_LENGTH, ciphertext_len);

    print_hex(cipher_email, ciphertext_len);

    int ct_result_len = decrypt_data(cipher_email, ciphertext_len, K_ab, iv, (unsigned char *)email);

    email[ct_result_len] = '\0';
    printf("Email ricevuta: %s\n", email);

    sleep(1); // altrimenti entrano in conflitto le due send e si sovrappongono

    unsigned char cipher_pw[CIPHER_LENGTH + IV_LENGTH];

    bytes_received = recv(sd, cipher_pw, sizeof(cipher_pw), 0);

    if (bytes_received < 0)
    {
        perror("SERVER error: Failed to get the encrypted password from the client.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Copia l'IV dai primi 'iv_len' byte del buffer ricevuto
    memcpy(iv, cipher_pw, IV_LENGTH);

    // Calcola la lunghezza effettiva del ciphertext
    ciphertext_len = bytes_received - IV_LENGTH;

    // Copia il ciphertext dal buffer (partendo dal byte 'iv_len' fino alla fine)
    memcpy(cipher_pw, cipher_pw + IV_LENGTH, ciphertext_len);

    print_hex(cipher_pw, ciphertext_len);

    ct_result_len = decrypt_data(cipher_pw, ciphertext_len, K_ab, iv, (unsigned char *)pw);

    pw[ct_result_len] = '\0';

    printf("Password ricevuta: %s\n", pw);
}

void *secureConnection(void *old_sd)
{
    ACCOUNT account;
    int sd = *((int *)old_sd);
    unsigned int key_len = 0;
    unsigned char result[MAX_RESULT_CHAR];
    ssize_t bytes_sent;
    int err;

    unsigned char *K_ab = handshake(sd, &key_len, account.username);

    err = client_control(sd, (unsigned char *)account.username, K_ab);

    if (err == 1) // client registrato
    {
        sprintf((char *)result, "%s", "found");
    }
    else if (err == 0) // client non registrato
    {
        sprintf((char *)result, "%s", "not_found");
    }
    else // ERRORE
    {
        sprintf((char *)result, "%s", "error");
    }

    unsigned char iv[IV_LENGTH];
    RAND_bytes(iv, IV_LENGTH);

    unsigned char cipher_result[CIPHER_LENGTH];
    int ct_result_len = encrypt_data(result, strlen((char *)result), K_ab, iv, cipher_result);

    unsigned char message_to_send[IV_LENGTH + ct_result_len];
    memcpy(message_to_send, iv, IV_LENGTH);
    memcpy(message_to_send + IV_LENGTH, cipher_result, ct_result_len);

    bytes_sent = send(sd, message_to_send, IV_LENGTH + ct_result_len, 0);

    if (bytes_sent <= 0)
    {
        perror("SERVER Error: Result of the search of the username -> send failure.\n");
        free(account.email);
        free(account.password);
        free(account.username);
        safe_exit(sd);
    }
    // ora funziona unicamente se l'utente vuole registrarsi ->
    // necessita' di fare una send nel client con y o n e una recv nel server da mettere in un if

    unsigned char cipher_ans[CIPHER_LENGTH + IV_LENGTH];
    char ans[MAX_RESULT_CHAR];

    ssize_t bytes_received = recv(sd, cipher_ans, sizeof(cipher_ans), 0);

    if (bytes_received < 0)
    {
        perror("SERVER error: Failed to get the encrypted password from the client.\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Copia l'IV dai primi 'iv_len' byte del buffer ricevuto
    memcpy(iv, cipher_ans, IV_LENGTH);

    // Calcola la lunghezza effettiva del ciphertext
    size_t ciphertext_len = bytes_received - IV_LENGTH;

    // Copia il ciphertext dal buffer (partendo dal byte 'iv_len' fino alla fine)
    memcpy(cipher_ans, cipher_ans + IV_LENGTH, ciphertext_len);

    print_hex(cipher_ans, ciphertext_len);

    ct_result_len = decrypt_data(cipher_ans, ciphertext_len, K_ab, iv, (unsigned char *)ans);

    ans[ct_result_len] = '\0';

    if (strcmp("registrazione", ans) == 0)
    {
        registration(sd, account.email, account.username, account.password, K_ab);
    }
    else if (strcmp("terminazione", ans) == 0)
    {
        puts("CLIENT disconnesso.");
    }

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