#include "../includes/ft_ping.h"


volatile __sig_atomic_t loop = 1;

// --- Signal handler to stop the loop ---
void interrupt_signal(int sig) 
{
    (void)sig;
    printf("\n"); // Move to a new line after ^C
    loop = 0;
}

int DNS_LookUp(t_ping_data *pdata) {
    struct addrinfo hints;
    struct addrinfo *result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int status = getaddrinfo(pdata->target_host, NULL, &hints, &result);
    if (status != 0) {
        fprintf(stderr, "ft_ping: %s: %s\n", pdata->target_host, gai_strerror(status));
        return (EXIT_FAILURE);
    }
    
    pdata->addr_info = result;
    struct sockaddr_in *addr_in = (struct sockaddr_in *)pdata->addr_info->ai_addr;
    inet_ntop(AF_INET, &addr_in->sin_addr, pdata->resolved_ip, INET_ADDRSTRLEN);
    return (EXIT_SUCCESS);
}



/**
 * @brief Creates a raw socket and sets a 1-second receive timeout.
 * @return The socket file descriptor on success, -1 on failure.
 */
int initialize_socket() 
{
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("ft_ping: socket error");
        return -1;
    }

    struct timeval tv_out = { .tv_sec = 1, .tv_usec = 0 };
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv_out, sizeof(tv_out)) < 0) {
        perror("ft_ping: setsockopt failed");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

void ping_loop(int sockfd, t_ping_data *pdata) {
    // Record the start time for the entire session
    gettimeofday(&pdata->stats.start_time, NULL);
    int seq_message = 1;

    while (loop) {
        char packet[PACKET_SIZE];
        create_packet(packet, seq_message);

        if (sendto(sockfd, packet, PACKET_SIZE, 0, pdata->addr_info->ai_addr, pdata->addr_info->ai_addrlen) > 0) {
            pdata->stats.packets_sent++;
        } else { /* ... error handling ... */ }

        char recv_buffer[1024];
        
        // NEW: Capture the source address of the reply
        struct sockaddr_storage from_addr;
        socklen_t from_len = sizeof(from_addr);

        ssize_t bytes_received = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, 
                                          (struct sockaddr *)&from_addr, &from_len);
        
        if (bytes_received > 0) {
            // Pass the reply address and stats struct for processing
            process_reply(recv_buffer, bytes_received, &from_addr, from_len, &pdata->stats);
        } else { /* ... error handling ... */ }
        
        seq_message++;
        if (loop) sleep(1);
    }

    // Record the end time for the session
    gettimeofday(&pdata->stats.end_time, NULL);
    printf("\n");
    print_summary(pdata->target_host, &pdata->stats);
}


/**
 * @brief Fills a buffer with a valid ICMP Echo Request packet.
 * @param packet The buffer to fill (must be at least PACKET_SIZE).
 * @param seq The sequence number for this packet.
 */
void create_packet(char *packet, int seq) 
{
    memset(packet, 0, PACKET_SIZE);
    
    struct icmphdr *ihdr = (struct icmphdr *)packet;
    ihdr->type = ICMP_ECHO;
    ihdr->code = 0;

    // The ID and sequence must be in network byte order BEFORE the checksum is calculated.
    ihdr->un.echo.id = htons(getpid());
    ihdr->un.echo.sequence = htons(seq);

    // The payload (timestamp) does not need byte-swapping, as it's just opaque data
    // that the remote host will echo back to us as-is.
    struct timeval *tv_payload = (struct timeval *)(packet + sizeof(struct icmphdr));
    gettimeofday(tv_payload, NULL);
    
    ihdr->checksum = 0;
    ihdr->checksum = checksum(packet, PACKET_SIZE);
}

// --- Main Function (Refactored and Cleaned) ---
int main(int ac, char *av[]) {
    if (ac < 2) {
        fprintf(stderr, "ft_ping: usage error: Destination address required\n");
        return EXIT_FAILURE;
    }

    t_ping_data pdata;
    memset(&pdata, 0, sizeof(pdata));

    pdata.stats.rtt_min = __DBL_MAX__; // Initialize min to a very large number
    pdata.stats.rtt_max = 0.0;

    pdata.target_host = av[1];

    if (DNS_LookUp(&pdata) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    int sockfd = initialize_socket();
    if (sockfd < 0) {
        freeaddrinfo(pdata.addr_info);
        return EXIT_FAILURE;
    }
    
    signal(SIGINT, interrupt_signal);

    printf("PING %s (%s) %d(%ld) bytes of data.\n",
           pdata.target_host, pdata.resolved_ip, PAYLOAD_SIZE, PACKET_SIZE + 20);

    ping_loop(sockfd, &pdata);

    close(sockfd);
    freeaddrinfo(pdata.addr_info);
    return EXIT_SUCCESS;
}