#ifndef FT_PING_H
#define FT_PING_H

#include <stdio.h>      // For printf
#include <stdlib.h>     // For EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>     // For memset, memcpy
#include <sys/types.h>  // For socket types
#include <sys/socket.h> // For sockets
#include <netdb.h>      // For getaddrinfo, gai_strerror
#include <arpa/inet.h>  // For inet_ntop
#include <netinet/ip_icmp.h>
#include <time.h>


#define PACKET_SIZE = 64;
#define ICMP_MINLEN = 8
#define RECV_TIMEOUT = 1
#define PING_SLEEP_RATE 1000000

int loop = 1;

typedef struct s_ping_data 
{
    char        *target_host;      // The original user input (e.g., "google.com")
    char        resolved_ip[INET_ADDRSTRLEN]; // The resolved IP string (e.g., "142.250.184.206")
    struct      addrinfo *addr_info;      // The full address info struct
} t_ping_data;

// typedef struct p_packet
// {
// struct icmp *imsg; // Header
// char msg[PACKET_SIZE - sizeof(struct icmphdr)];
// };


int DNS_LookUp(t_ping_data *pdata);
void make_ICMP_message(uint8_t **msg, size_t *msg_len);


#endif
