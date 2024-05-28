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

#define _POSIX_C_SOURCE 200809L
#define MAX_CLIENTS 2
#define MAX_USER_CHAR 128
#define MAX_REQUEST_SIZE (64 * 1024)
#define NONCE_LEN 16
#define COMMAND_DIM 100

/*
    Handler function.
*/
void handler(int signo){
    int status;
    (void)signo;

    while (waitpid(-1, &status, WNOHANG) > 0)
        continue;
}

void disconnect(int sd){
    close(sd);
    puts("\n-----(Client Disconnected)-----\n");
    puts("\nok\n");
}

unsigned char *handshake(int client_sd, unsigned int *k_len, char *client_name){
    // Handshake Setup

    // S1) Receive <Client Nonce>
    unsigned char nonce_client[NONCE_LEN];
    ssize_t bytes_cm1 = recv(client_sd, nonce_client, sizeof(nonce_client), 0);
    if(!bytes_cm1){
        perror("SERVER Error: handshake() -> (S1) client nonce recv() failure.\n");
        free(nonce_client);
        close(client_sd);
        pthread_exit(NULL); 
    }

    printf("\nServer(H-S1): <Client Nonce> received.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++){
        printf("%x ", nonce_client[i]);
    }
    printf("\n");
    
    // S2) <Server Nonce> creation
    unsigned char nonce_server[NONCE_LEN];
    int result_nonce = fresh_nonce(&nonce_server);
    if(!result_nonce){
        perror("SERVER Error: handshake() -> recv() failure.\n");
        free(nonce_server);
        disconnect(client_sd);
        pthread_exit(NULL); 
    }

    printf("\nServer(H-S2): <Server Nonce> creation successful.\n-> ");
    for (int i = 0; i < NONCE_LEN; i++){
        printf("%x ", nonce_server[i]);
    }
    printf("\n");

    return nonce_server;
}


void* operations(void *osd){
    char *user = "";
    int sd = *((int*)osd);
    unsigned int key_len = 0;

    unsigned char *k_ab = handshake(sd, &key_len, &user);
    unsigned char *k_ab = handshake(sd, &key_len, &user);
    if (k_ab == NULL) {
        pthread_exit(NULL); // Exit if handshake failed
    }

    close(sd);
    pthread_exit(NULL);
}

void error(const char *msg) {
    perror(msg);
    exit(1);
}

/*
    Server main function
*/
int main(int argc, char **argv){
    // Server Setup
    int sd, err, pid, status, on;
    int *ns = (int*)malloc(sizeof(int));

    struct addrinfo hints, *res;
    struct sigaction sa;
    pthread_t t_id;

    // Input Arguments Check
    if(argc != 2){
        fprintf(stderr, "\nSERVER Error: too many arguments, write as: ./server port");
        exit(EXIT_FAILURE);
    }

    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sa.sa_handler = handler;

    if (sigaction(SIGCHLD, &sa, NULL) == -1){
        perror("\nSERVER Error: main() -> sigaction() failure");
        exit(EXIT_FAILURE);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if ((err = getaddrinfo(NULL, argv[1], &hints, &res)) != 0){
        perror("\nSERVER Error: main() -> getaddrinfo() failure");
        exit(EXIT_FAILURE);
    }

    if ((sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0){
        perror("\nSERVER Error: main() -> socket() failure.");
        exit(EXIT_FAILURE);
    }

    on = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
        perror("\nSERVER Error: main() -> setsockopt() failure.");
        exit(EXIT_FAILURE);
    }

    if (bind(sd, res->ai_addr, res->ai_addrlen) < 0){
        perror("\nSERVER Error: main() -> bind() failure.");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(res);

    if (listen(sd, SOMAXCONN) < 0){
        perror("\nSERVER Error: main() -> listen() failure.");
        exit(EXIT_FAILURE);
    }

    for (;;){
        puts("\nServer: listening for <Client>...");

        if ((*ns = accept(sd, NULL, NULL)) < 0){
            perror("\nSERVER Error: main() -> accept() failure.");
            exit(EXIT_FAILURE);
        }

        if (pthread_create(&t_id, NULL, operations, (void *)ns)){ // crea un nuovo thread che gestisce il socket client-server
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
/*
// Function prototype for client handling function
void *handle_client(void *arg);

int main(int argc, char **argv) {
    int sockfd, newsockfd, portno;
    socklen_t clilen;
    struct sockaddr_in serv_addr, cli_addr;
    pthread_t threads[MAX_CLIENTS]; // Array to hold thread IDs
    int thread_index = 0; // Index for the threads array

    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        error("ERROR opening socket");

    // Initialize server address structure
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    portno = argv[2];
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    // Input Arguments Check
    if(argc != 2){
        error("\nSERVER Error: too many arguments, write as: ./server port");
    }

    // Bind the socket to the address
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
        error("ERROR on binding");

    // Listen for incoming connections
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    // Server loop
    while (1) {
        // Accept connection from client
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
        if (newsockfd < 0) 
            error("ERROR on accept");

        // Create a new thread to handle client
        if (pthread_create(&threads[thread_index], NULL, handle_client, (void *)&newsockfd) != 0) {
            fprintf(stderr, "ERROR creating thread\n");
            close(newsockfd);
        }

        // Increment thread index and reset if it reaches MAX_CLIENTS
        thread_index++;
        if (thread_index >= MAX_CLIENTS)
            thread_index = 0;
    }

    close(sockfd);
    return 0; 
}
*/