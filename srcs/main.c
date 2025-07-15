#include "../includes/ft_ping.h"


volatile __sig_atomic_t loop = 1;

// --- Signal handler to stop the loop ---
void interrupt_signal(int sig) 
{
    (void)sig;
    printf("\n"); // Move to a new line after ^C
    loop = 0;
}

int DNS_LookUp(t_ping_data *pdata)
{
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int status = getaddrinfo(pdata->target_host, NULL, &hints, &result);
    if (status != 0)
    {
        fprintf(stderr, "ft_ping: %s: %s\n", pdata->target_host, gai_strerror(status));
        return (EXIT_FAILURE);
    }
    
    pdata->addr_info = result;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)pdata->addr_info->ai_addr;
    inet_ntop(AF_INET, &addr_in->sin_addr, pdata->resolved_ip, INET_ADDRSTRLEN);
    return (EXIT_SUCCESS);
}

int initialize_socket(t_ping_data *pdata) 
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("ft_ping: socket error");
        return (-1);
    }
    printf("%d---\n", pdata->W_timeout);
    struct timeval tv_out = { .tv_sec = pdata->W_timeout, .tv_usec = 0 };
    int ttl = (pdata->opt_ttl == -1) ? 64 : pdata->opt_ttl;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0 ||
        setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        perror("ft_ping: setsockopt failed");
        close(sockfd);
        return (-1);
    }
    return sockfd;
}

void ping_loop(int sockfd, t_ping_data *pdata)
{
    // Record the start time for the entire session
    gettimeofday(&pdata->stats.start_time, NULL);
    int seq_message = 1;
    struct timeval now;
    int timeout_val = pdata->w_timeout;
    int packet_size = sizeof(struct icmphdr) + pdata->payload_size;

    while (loop)
    {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - pdata->stats.start_time.tv_sec);

        if (timeout_val > 0 && elapsed >= timeout_val)
            break ;

        char packet[packet_size];
        create_packet(packet, seq_message, pdata->payload_size);

        if (sendto(sockfd, packet, packet_size, 0, pdata->addr_info->ai_addr, pdata->addr_info->ai_addrlen) > 0)
            pdata->stats.packets_sent++;
        else { write(1, "1\n", 2); }

        char recv_buffer[1024];
        
        // Capture the source address of the reply
        struct sockaddr_storage from_addr;
        socklen_t from_len = sizeof(from_addr);

        ssize_t bytes_received = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, 
                                          (struct sockaddr *)&from_addr, &from_len);
        
        if (bytes_received > 0)
            // Pass the reply address and stats struct for processing
            process_reply(recv_buffer, bytes_received, &from_addr, pdata);
        else { fprintf(stderr, "Request timeout for icmp_seq %d\n", seq_message); }
        
        seq_message++;
        if (loop) sleep(1);
    }

    // Record the end time for the session
    gettimeofday(&pdata->stats.end_time, NULL);
    print_summary(pdata->target_host, &pdata->stats);
}

void create_packet(char *packet, int seq, unsigned int payload_size) 
{
    unsigned int packet_size = sizeof(struct icmphdr) + payload_size;
    memset(packet, 0, packet_size);

    struct icmphdr *ihdr = (struct icmphdr *)packet;
    ihdr->type = ICMP_ECHO;
    ihdr->code = 0;

    ihdr->un.echo.id = htons(getpid());
    ihdr->un.echo.sequence = htons(seq);

    // Insert timestamp in payload start if enough space
    if (payload_size >= sizeof(struct timeval)) {
        struct timeval *tv_payload = (struct timeval *)(packet + sizeof(struct icmphdr));
        gettimeofday(tv_payload, NULL);

        // Optionally fill remaining payload with zeros or pattern
        if (payload_size > sizeof(struct timeval)) {
            memset(packet + sizeof(struct icmphdr) + sizeof(struct timeval), 0,
                   payload_size - sizeof(struct timeval));
        }
    } else {
        // If payload too small, just zero it all
        memset(packet + sizeof(struct icmphdr), 0, payload_size);
    }

    ihdr->checksum = 0;
    ihdr->checksum = checksum(packet, packet_size);
}

int main(int ac, char *av[]) 
{
    if (ac < 2)
    {
        fprintf(stderr, "ft_ping: usage error: Destination address required\n");
        return EXIT_FAILURE;
    }

    t_ping_data pdata;
    memset(&pdata, 0, sizeof(pdata));

    parse_arguments(ac, av, &pdata);

    unsigned int packet_size = sizeof(struct icmphdr) + pdata.payload_size;

    if (pdata.target_host == NULL) {
        fprintf(stderr, "ft_ping: usage error: Destination address required\n");
        return EXIT_FAILURE;
    }

    pdata.stats.rtt_min = __DBL_MAX__; // Initialize min to a very large number
    pdata.stats.rtt_max = 0.0;

    if (DNS_LookUp(&pdata))
        return EXIT_FAILURE;

    int sockfd = initialize_socket(&pdata);
    if (sockfd < 0)
        return (freeaddrinfo(pdata.addr_info), EXIT_FAILURE);
    
    signal(SIGINT, interrupt_signal);

    printf("PING %s (%s) %d(%d) bytes of data.\n",
           pdata.target_host, pdata.resolved_ip, pdata.payload_size, packet_size + 20);

    ping_loop(sockfd, &pdata);

    close(sockfd);
    freeaddrinfo(pdata.addr_info);
    return (EXIT_SUCCESS);
}