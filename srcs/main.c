#include "../includes/ft_ping.h"


int main(int ac, char *av[])
{
    if (ac < 2)
        return (printf("ft_ping: usage error: Destination address required\n"), EXIT_FAILURE);

    const char *hostname = av[1];

    struct addrinfo hint;
    struct addrinfo *result;

    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;
    result = NULL;

    int status = getaddrinfo(hostname, NULL, &hint, &result);

    if (status)
        return (printf("ft_ping: internal error: getaddrinfo failed!\n"), EXIT_FAILURE);

    struct addrinfo *tmp = result;
    while (tmp != NULL)
    {
        printf("Entry:\n");
        printf("\tType: %i\n", tmp->ai_socktype);
        printf("\tFamily: %i", tmp->ai_family);

        char adress_string[INET_ADDRSTRLEN];
        void *addr;
        if (tmp->ai_family == AF_INET)
        {
            addr = &((struct sockaddr_in *)tmp->ai_addr)->sin_addr;
            inet_ntop(tmp->ai_family, addr, adress_string, INET_ADDRSTRLEN);
        }

        printf("\tAdress: %s", adress_string);
        tmp = tmp->ai_next;
    }

    printf("%d\n", status);

    freeaddrinfo(result);
    
    return (EXIT_SUCCESS);
}