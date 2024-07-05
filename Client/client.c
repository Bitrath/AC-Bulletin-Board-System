#define _POSIX_C_SOURCE 200809L
#define MAX_REQUEST_SIZE (64 * 1024)
#define NONCE_LEN 16
#define MAX_USER_CHAR 32
#define MAX_PW_CHAR 32
#define MAX_RESULT_CHAR 16
#define CIPHER_LENGTH 128
#define IV_LENGTH 16
#define OP_LEN 4
#include <time.h>
#include <netdb.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <regex.h>
#include <ctype.h>
#include "../Utils/rxb.h"
#include "../Utils/utils.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include "../Utils/Dif_Hel.h"
#include "../Utils/digital_signature.h"
#include "../Utils/Enc_Dec.h"

// Funzione per stampare i dati in formato esadecimale
void print_hex(const char *title, const unsigned char *data, size_t len)
{
    printf("%s:", title);
    for (size_t i = 0; i < len; i++)
    {
        printf(" %02x", data[i]);
    }
    printf("\n");
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

void clean_stdin(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
    {
    }
}

void t_disconnect(int sd)
{
    close(sd);
    puts("--- <Disconnected from the server> ---");
}

void client_control(int sd, char *user, unsigned char *K_ab)
{
    // --- CONTROLLO PRESENZA DELL'UTENTE TRA QUELLI REGISTRATI ---

    ssize_t bytes_sent;

    puts("Inserire il username: ");
    if (fgets(user, MAX_USER_CHAR, stdin) < 0)
    {
        fprintf(stderr, "Errore fgets user");
        exit(EXIT_FAILURE);
    }
    else if (strlen(user) >= MAX_USER_CHAR - 1)
    {
        fprintf(stderr, "L'username inserito e' troppo lungo. (> 32 char)\n");
        exit(EXIT_FAILURE);
    }

    unsigned char cipher_user[CIPHER_LENGTH];

    unsigned char iv[IV_LENGTH];
    RAND_bytes(iv, IV_LENGTH);

    int ct_user_len = encrypt_data((unsigned char *)user, strlen(user), K_ab, iv, cipher_user);

    // Invio dell'IV e del ciphertext
    unsigned char message_to_send[IV_LENGTH + ct_user_len];
    memcpy(message_to_send, iv, IV_LENGTH);
    memcpy(message_to_send + IV_LENGTH, cipher_user, ct_user_len);

    bytes_sent = send(sd, message_to_send, IV_LENGTH + ct_user_len, 0);

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
    printf("\nSIZES: signature(%u) test_message(%zu)", *server_sig_length, test_sig_length);

    // printf("\n(TEST M): <nonce_c + dh_s_pk>\n-> %hhu\n", *test_signature);

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

    // With the last recv the client has received and did the verification of the server, now the client needs to verify himself
    // with the digital envelope method.

    // DIGITAL ENVELOPE CLIENT VERIFICATION

    puts("--- END CLIENT HANDSHAKE with SERVER ---");

    return session_key;
}

int is_valid_email(char *email) // da aggiustare, non worka
{
    regex_t regex;
    int reti;
    char msgbuf[100];
    size_t email_len = strlen(email);
    email[email_len - 1] = '\0';

    // Definizione del pattern per una email, inclusi i simboli % e altri caratteri validi
    const char *pattern = "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$";

    // Compila l'espressione regolare
    reti = regcomp(&regex, pattern, REG_EXTENDED);
    if (reti)
    {
        fprintf(stderr, "Could not compile regex\n");
        return 0;
    }

    // Confronta l'email con il pattern
    reti = regexec(&regex, email, 0, NULL, 0);
    if (!reti)
    {
        regfree(&regex); // Libera la memoria allocata per l'espressione regolare
        return 1;        // Email valida
    }
    else if (reti == REG_NOMATCH)
    {
        regfree(&regex); // Libera la memoria allocata per l'espressione regolare
        return 0;        // Email non valida
    }
    else
    {
        regerror(reti, &regex, msgbuf, sizeof(msgbuf));
        fprintf(stderr, "Regex match failed: %s\n", msgbuf);
        regfree(&regex); // Libera la memoria allocata per l'espressione regolare
        return 0;
    }
}

void registration(int sd, char *email, char *user, char *pw, unsigned char *K_ab)
{
    ssize_t bytes_sent;

    // Encrypting delle credenziali da inviare al server //

    while (true)
    {
        puts("Inserire la email: ");
        if (fgets(email, MAX_USER_CHAR, stdin) < 0)
        {
            fprintf(stderr, "Errore fgets email");
            exit(EXIT_FAILURE);
        }
        else if (strlen(email) >= MAX_USER_CHAR - 1)
        {
            fprintf(stderr, "La email inserita e' troppo lunga. (> 32 char)\n");
            clean_stdin(); // serve per evitare che nella fgets successiva mantenga i char inseriti che sforano la lunghezza di 32 byte
            continue;
        }
        else
            break;
    }

    while (true)
    {
        puts("Inserire la password: ");
        if (fgets(pw, MAX_PW_CHAR, stdin) < 0)
        {
            fprintf(stderr, "Errore fgets pw");
            exit(EXIT_FAILURE);
        }
        else if (strlen(pw) >= MAX_PW_CHAR - 1)
        {
            fprintf(stderr, "La password inserita e' troppo lunga. (> 32 char)\n");
            clean_stdin();
            continue;
        }
        else if (strlen(pw) < 6)
        {
            fprintf(stderr, "La password inserita e' troppo corta. (< 6 char)\n");
            continue;
        }
        else
            break;
    }

    unsigned char iv[IV_LENGTH];
    RAND_bytes(iv, IV_LENGTH);

    unsigned char cipher_email[CIPHER_LENGTH];

    int ct_email_len = encrypt_data((unsigned char *)email, strlen(email), K_ab, iv, cipher_email);

    unsigned char email_to_send[IV_LENGTH + ct_email_len];
    memcpy(email_to_send, iv, IV_LENGTH);
    memcpy(email_to_send + IV_LENGTH, cipher_email, ct_email_len);

    bytes_sent = send(sd, email_to_send, IV_LENGTH + ct_email_len, 0);

    if (bytes_sent <= 0)
    {
        perror("Errore send");
        exit(EXIT_FAILURE);
    }

    sleep(1); // altrimenti entrano in conflitto le due receive e si sovrappongono

    RAND_bytes(iv, IV_LENGTH);
    unsigned char cipher_pw[CIPHER_LENGTH];

    int ct_pw_len = encrypt_data((unsigned char *)pw, strlen(pw), K_ab, iv, cipher_pw);

    unsigned char pw_to_send[IV_LENGTH + ct_pw_len];
    memcpy(pw_to_send, iv, IV_LENGTH);
    memcpy(pw_to_send + IV_LENGTH, cipher_pw, ct_pw_len);

    bytes_sent = send(sd, pw_to_send, IV_LENGTH + ct_pw_len, 0);

    if (bytes_sent <= 0)
    {
        perror("Errore send");
        exit(EXIT_FAILURE);
    }
}

void vip_mode(int sd, char *email, char *user, char *pw, unsigned char *K_ab)
{
    char op[OP_LEN];

    while (true)
    {
        puts("Selezionare l'operazione da eseguire:");
        puts("1) List n last available messages.\n2) Get msg by id.\n3) Add msg to BBS.");

        if (fgets(op, sizeof(op), stdin) == NULL)
        {
            fprintf(stderr, "Errore nella lettura dell'input\n");
            exit(EXIT_FAILURE);
        }

        op[1] = '\0';

        if (strcmp("1", op) == 0)
        {
            char num[OP_LEN];
            unsigned char iv[IV_LENGTH];

            puts("Selezionare il numero di messaggi visualizzabili: (max 9)");

            do
            {
                if (fgets(num, sizeof(num), stdin) == NULL)
                {
                    fprintf(stderr, "Errore nella lettura dell'input\n");
                    exit(EXIT_FAILURE);
                }

                num[1] = '\0';

            } while (!(strlen(num) == 1 && isdigit(num[0]) && num[0] >= '1' && num[0] <= '9'));

            char msg_to_send[MAX_RESULT_CHAR];
            snprintf(msg_to_send, sizeof(msg_to_send), "list: %s", num);
            puts(msg_to_send);

            // Genera IV casuale
            if (RAND_bytes(iv, IV_LENGTH) != 1)
            {
                fprintf(stderr, "Errore nella generazione dell'IV\n");
                exit(EXIT_FAILURE);
            }

            unsigned char cipher_result[CIPHER_LENGTH];
            int ct_result_len = encrypt_data(msg_to_send, strlen((char *)msg_to_send), K_ab, iv, cipher_result);

            unsigned char message_to_send[IV_LENGTH + ct_result_len];
            memcpy(message_to_send, iv, IV_LENGTH);
            memcpy(message_to_send + IV_LENGTH, cipher_result, ct_result_len);

            ssize_t bytes_sent = send(sd, message_to_send, IV_LENGTH + ct_result_len, 0);

            if (bytes_sent <= 0)
            {
                perror("SERVER Error: Result of the search -> send failure.\n");
                exit(EXIT_FAILURE);
            }
        }
        else if (strcmp("2", op) == 0)
        {
            puts("Get msg by id");
            // Implementa qui la logica per "Get msg by id"
        }
        else if (strcmp("3", op) == 0)
        {
            puts("Add msg to BBS");
            // Implementa qui la logica per "Add msg to BBS"
        }
        else
        {
            puts("Operazione non valida. Si prega di selezionare un'opzione tra 1, 2 e 3.");
        }
    }
}

int main(int argc, char **argv)
{
    int err, sd;
    struct addrinfo hints, *res, *ptr;
    ACCOUNT account;

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

    client_control(sd, account.username, K_ab);

    unsigned char cipher_result[CIPHER_LENGTH];
    unsigned char result[MAX_RESULT_CHAR];
    unsigned char iv[IV_LENGTH];

    ssize_t bytes_received = recv(sd, cipher_result, sizeof(cipher_result), 0);

    if (bytes_received < 0)
    {
        perror("CLIENT Error: Failed to get the result of the user search from the server\n");
        close(sd);
        exit(EXIT_FAILURE);
    }

    // Copia l'IV dai primi 'iv_len' byte del buffer ricevuto
    memcpy(iv, cipher_result, IV_LENGTH);

    // Calcola la lunghezza effettiva del ciphertext
    size_t ciphertext_len = bytes_received - IV_LENGTH;

    // Copia il ciphertext dal buffer (partendo dal byte 'iv_len' fino alla fine)
    memcpy(cipher_result, cipher_result + IV_LENGTH, ciphertext_len);

    // decrypting del risultato della ricerca dell'user nel DB

    int ct_result_len = decrypt_data(cipher_result, ciphertext_len, K_ab, iv, result);

    if (strcmp((char *)result, "found") == 0) // client registrato
    {
        puts("Client registrato, login in corso...");
        registration(sd, account.email, account.username, account.password, K_ab);

        // controllo esito login

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

        // Calcola la salt_len effettiva del ciphertext
        size_t ciphertext_len = bytes_received - IV_LENGTH;

        // Copia il ciphertext dal buffer (partendo dal byte 'iv_len' fino alla fine)
        memcpy(cipher_ans, cipher_ans + IV_LENGTH, ciphertext_len);

        ct_result_len = decrypt_data(cipher_ans, ciphertext_len, K_ab, iv, (unsigned char *)ans);

        ans[ct_result_len] = '\0';

        if (strcmp("SUCCESS", ans) == 0)
        {
            puts("CLIENT loggato con successo.");
            vip_mode(sd, account.email, account.username, account.password, K_ab);
        }
        else if (strcmp("FAILURE", ans) == 0)
        {
            puts("CLIENT non riconosciuto: disconnesso.");
            exit(EXIT_FAILURE);
        }
    }
    else if (strcmp((char *)result, "not_found") == 0) // client non registrato
    {
        char c;

        while (true)
        {
            puts("Utente non registrato nell'archivio, procedere con la registrazione? Y - N ");

            c = getchar(); // legge un solo carattere

            // svuota il buffer di input fino alla fine della riga
            while (getchar() != '\n')
                ;

            if (c == 'y' || c == 'Y')
            {
                // send registration request

                puts("REGISTRAZIONE in corso...");
                unsigned char iv[IV_LENGTH];
                RAND_bytes(iv, IV_LENGTH);
                char ans[MAX_RESULT_CHAR];
                unsigned char cipher_ans[CIPHER_LENGTH];

                sprintf(ans, "registrazione");

                int ct_ans_len = encrypt_data((unsigned char *)ans, strlen(ans), K_ab, iv, cipher_ans);

                // Invio dell'IV e del ciphertext
                unsigned char message_to_send[IV_LENGTH + ct_ans_len];
                memcpy(message_to_send, iv, IV_LENGTH);
                memcpy(message_to_send + IV_LENGTH, cipher_ans, ct_ans_len);

                ssize_t bytes_sent = send(sd, message_to_send, IV_LENGTH + ct_ans_len, 0);

                if (bytes_sent < 0)
                {
                    perror("Errore send");
                    exit(EXIT_FAILURE);
                }
                sleep(1);
                registration(sd, account.email, account.username, account.password, K_ab);
                break;
            }
            else if (c == 'n' || c == 'N')
            {
                puts("Terminazione Comunicazione.");

                unsigned char iv[IV_LENGTH];
                RAND_bytes(iv, IV_LENGTH);
                char ans[MAX_RESULT_CHAR];
                unsigned char cipher_ans[CIPHER_LENGTH];

                sprintf(ans, "terminazione");

                int ct_ans_len = encrypt_data((unsigned char *)ans, strlen(ans), K_ab, iv, cipher_ans);

                // Invio dell'IV e del ciphertext
                unsigned char message_to_send[IV_LENGTH + ct_ans_len];
                memcpy(message_to_send, iv, IV_LENGTH);
                memcpy(message_to_send + IV_LENGTH, cipher_ans, ct_ans_len);

                ssize_t bytes_sent = send(sd, message_to_send, IV_LENGTH + ct_ans_len, 0);

                if (bytes_sent < 0)
                {
                    perror("Errore send");
                    exit(EXIT_FAILURE);
                }

                close(sd);
                exit(EXIT_SUCCESS);
            }
            else
            {
                perror("Errore nella risposta.");
                continue;
            }
        }
    }
    else
    {
        perror("SERVER Error: Failed to get the result of the user search from the server");
        exit(EXIT_FAILURE);
    }

    close(sd);
    return 0;
}