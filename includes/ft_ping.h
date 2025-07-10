#ifndef FT_PING_H
#define FT_PING_H

#include <stdio.h>      // For printf
#include <stdlib.h>     // For EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>     // For memset, memcpy
#include <sys/types.h>  // For socket types
#include <sys/socket.h> // For sockets
#include <netdb.h>      // For getaddrinfo, gai_strerror
#include <arpa/inet.h>  // For inet_ntop
#include <unistd.h>
#include <signal.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <errno.h>
#include <math.h>


#define PAYLOAD_SIZE 56
#define PACKET_SIZE (sizeof(struct icmphdr) + PAYLOAD_SIZE)

typedef struct s_ping_stats {
    long            packets_sent;
    long            packets_received;
    double          rtt_min;
    double          rtt_max;
    double          rtt_total;      // Sum of all RTTs for average
    double          rtt_total_sq;   // Sum of all (RTT * RTT) for std deviation
    struct timeval  start_time;
    struct timeval  end_time;
} t_ping_stats;


typedef struct s_ping_data {
    char            *target_host;
    struct addrinfo *addr_info;
    char            resolved_ip[INET_ADDRSTRLEN];
    t_ping_stats    stats; // Embed the stats struct
} t_ping_data;


unsigned short checksum(void *addr, int len);
void interrupt_signal(int sig);
int DNS_LookUp(t_ping_data *pdata);
int initialize_socket();
void ping_loop(int sockfd, t_ping_data *pdata);
void create_packet(char *packet, int seq);
void process_reply(char *buffer, ssize_t len, struct sockaddr_storage *from_addr, socklen_t from_len, t_ping_stats *stats);
void print_summary(char *host, t_ping_stats *stats);
void perform_reverse_dns(struct sockaddr_storage *from_addr, socklen_t from_len, char *buffer, size_t len);


#endif
