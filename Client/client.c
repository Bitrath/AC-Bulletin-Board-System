#define _POSIX_C_SOURCE 200809L
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "../Utils/rxb.h"
#include "../Utils/utils.h"

#define MAX_REQUEST_SIZE (64 * 1024)

int main(int argc, char **argv)
{

    int err, sd;
    struct addrinfo hints, *res, *ptr;
    rxb_t rxb;

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

    rxb_init(&rxb, MAX_REQUEST_SIZE);

    for (;;)
    {
        char user[128];

        puts("Inserire lo username: (fine per terminare)"); // inserisco lo user per effettuare il login
        if (fgets(user, sizeof(user), stdin) < 0)
        {
            fprintf(stderr, "Errore fgets user");
            exit(EXIT_FAILURE);
        }

        if (strcmp(user, "fine\n") == 0)
        {
            exit(EXIT_SUCCESS);
        }

        if (write_all(sd, user, strlen(user)) < 0)
        {
            fprintf(stderr, "Errore write_all user");
            exit(EXIT_FAILURE);
        }

        for (;;)
        {
            char response[MAX_REQUEST_SIZE];
            size_t response_len;

            memset(&response, 0, sizeof(response));
            response_len = sizeof(response) - 1;

            if (rxb_readline(&rxb, sd, response, &response_len))
            {
                fprintf(stderr, "Errore readline response");
                rxb_destroy(&rxb);
                close(sd);
                exit(EXIT_FAILURE);
            }

            puts(response);

            if (strcmp(response, "--- END REQUEST ---") == 0)
            {
                break;
            }
        }
    }
    close(sd);
    return 0;
}