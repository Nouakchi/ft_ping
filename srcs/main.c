#include "../includes/ft_ping.h"
#include <stdio.h>

int main(int ac, char *av[])
{
    if (ac < 2)
        return (printf("ft_ping: usage error: Destination address required\n"), 0);

    printf("%s", av[0]);
    
    return (0);
}