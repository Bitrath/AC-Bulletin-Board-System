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
#include "../Utils/utils.h"

#define _POSIX_C_SOURCE 200809L
#define MAX_REQUEST_SIZE (64 * 1024)
#define NONCE_LEN 16
#define MAX_USER_CHAR 128

void *handshake(int sd){
    // Client Handshake Setup

    // C1) Client Nonce
    unsigned char nonce_client[NONCE_LEN];
    int result_cn = fresh_nonce(&nonce_client);
    if(!result_cn){
        perror("CLIENT Error: handshake() -> (C1) nonce creation failure.\n");
        free(nonce_client);
        close(sd);
        exit(1);
    }

    printf("\nClient(H-C1): <Client Nonce> creation successful.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++){
        printf("%x ", nonce_client[i]);
    }
    printf("\n");

    // C2) Send <Client Nonce> to <Server>
    printf("\nClient(H-C2): <Client Nonce> to <Server>");
    ssize_t bytes_m1 = send(sd, nonce_client, sizeof(nonce_client), 0);
    if(!bytes_m1){
        perror("CLIENT Error: handshake() -> (C2) nonce send() failure.\n");
        free(nonce_client);
        close(sd);
        exit(EXIT_FAILURE);;
    }

    return nonce_client;
}

int main(int argc, char **argv){
    int err, sd;
    struct addrinfo hints, *res, *ptr;

    if (argc != 3){
        fprintf(stderr, "\nCLIENT Error: arguments failure. Write as: ./client host port \n");
        exit(EXIT_FAILURE);
    }

    signal(SIGCHLD, SIG_IGN);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((err = getaddrinfo(argv[1], argv[2], &hints, &res)) != 0){
        fprintf(stderr, "CLIENT Error: main() -> (getaddrinfo) failure\n");
        exit(EXIT_FAILURE);
    }

    for (ptr = res; ptr != NULL; ptr = ptr->ai_next){
        if ((sd = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol)) < 0){
            fprintf(stderr, "CLIENT Error: main() -> (socket) failure\n");
            continue;
        }
        if (connect(sd, ptr->ai_addr, ptr->ai_addrlen) == 0){
            puts("\nClient: <Connection> to <Server> success.");
            break;
        }
        close(sd);
    }

    if (ptr == NULL){
        fprintf(stderr, "CLIENT Error: main() -> (fallback) failure\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    unsigned char *K_ab = handshake(sd);

    close(sd);
    return 0;
}