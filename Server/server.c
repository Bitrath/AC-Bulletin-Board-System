#define _POSIX_C_SOURCE 200809L
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
#include "utils.h"
#include "rxb.h"

#define MAX_REQUEST_SIZE (64 * 1024)

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

void *secureConnection(void *old_sd)
{
    char user[] = "";
    int sd = *((int *)old_sd);
    unsigned int key_len = 0;

    t_disconnect(sd);
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

    signal(SIGPIPE, SIG_IGN);

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

        close(*ns);
    }
    close(sd);
    return 0;
}