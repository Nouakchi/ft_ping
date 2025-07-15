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
#include <stdbool.h>



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
    int             opt_verbose;
    int             opt_ttl;
    bool            rev_dns;
    int             W_timeout;
    int             w_timeout;
    unsigned int    payload_size;
    char            *target_host;
    struct addrinfo *addr_info;
    char            resolved_ip[INET_ADDRSTRLEN];
    t_ping_stats    stats; // Embed the stats struct
} t_ping_data;


void print_usage(void);
int initialize_socket(t_ping_data *pdata);
void interrupt_signal(int sig);
int DNS_LookUp(t_ping_data *pdata);
void create_packet(char *packet, int seq, unsigned int payload_size);
unsigned short checksum(void *addr, int len);
void ping_loop(int sockfd, t_ping_data *pdata);
void print_summary(char *host, t_ping_stats *stats);
void print_icmp_error_details(struct icmphdr *icmp_hdr);
void parse_arguments(int ac, char *av[], t_ping_data *pdata);
double calculate_and_update_rtt(struct timeval *tv_sent, t_ping_stats *stats);
void perform_reverse_dns(struct sockaddr_storage *from_addr, socklen_t from_len, char *buffer, size_t len);
void handle_echo_reply(char *buffer, int ip_hdr_len, struct ip *ip_hdr, struct icmphdr *icmp_hdr, t_ping_data *pdata);
void process_reply(char *buffer, ssize_t len, struct sockaddr_storage *from_addr, t_ping_data *pdata);
void handle_verbose_reply(char *buffer, int ip_hdr_len, struct icmphdr *icmp_hdr, struct sockaddr_storage *from_addr);

#endif
