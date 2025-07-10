#include "ft_ping.h"

unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

/**
 * @brief Prints the final ping statistics summary.
 * @param host The target hostname or IP address.
 * @param sent The total number of packets sent.
 * @param received The total number of packets received.
 */
void print_summary(char *host, t_ping_stats *stats) {
    printf("--- %s ping statistics ---\n", host);

    double loss = 0;
    if (stats->packets_sent > 0) {
        loss = ((double)(stats->packets_sent - stats->packets_received) / stats->packets_sent) * 100.0;
    }
    
    double total_time_ms = (stats->end_time.tv_sec - stats->start_time.tv_sec) * 1000.0 +
                           (stats->end_time.tv_usec - stats->start_time.tv_usec) / 1000.0;

    printf("%ld packets transmitted, %ld received, %.0f%% packet loss, time %.0fms\n",
           stats->packets_sent, stats->packets_received, loss, total_time_ms);

    if (stats->packets_received > 0) {
        double rtt_avg = stats->rtt_total / stats->packets_received;
        double rtt_mdev = sqrt(stats->rtt_total_sq / stats->packets_received - rtt_avg * rtt_avg);
        printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
               stats->rtt_min, rtt_avg, stats->rtt_max, rtt_mdev);
    }
}

/**
 * @brief Performs a reverse DNS lookup to get the hostname from an address.
 * @param from_addr The address structure of the replying host.
 * @param from_len The length of the address structure.
 * @param buffer Buffer to store the resulting hostname.
 * @param len Size of the buffer.
 */
void perform_reverse_dns(struct sockaddr_storage *from_addr, socklen_t from_len, char *buffer, size_t len) {
    if (getnameinfo((struct sockaddr *)from_addr, from_len, buffer, len, NULL, 0, 0) != 0) {
        // If lookup fails, just use the IP address from the reply
        inet_ntop(from_addr->ss_family, 
                  &(((struct sockaddr_in *)from_addr)->sin_addr), 
                  buffer, len);
    }
}

/**
 * @brief Parses a received packet, validates it, and prints the result.
 * @param buffer The buffer containing the received data (IP header + ICMP).
 * @param len The number of bytes received.
 * @param ip_str The resolved IP address string for printing.
 * @param packets_received Pointer to the counter for received packets.
 */
void process_reply(char *buffer, ssize_t len, struct sockaddr_storage *from_addr, socklen_t from_len, t_ping_stats *stats) {
    struct ip *ip_hdr = (struct ip *)buffer;
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    if (len < ip_hdr_len + (ssize_t)sizeof(struct icmphdr)) return;

    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ip_hdr_len);

    if (icmp_hdr->type == ICMP_ECHOREPLY && ntohs(icmp_hdr->un.echo.id) == getpid()) {
        stats->packets_received++;
        
        struct timeval time_received;
        gettimeofday(&time_received, NULL);
        
        struct timeval *tv_sent = (struct timeval *)(buffer + ip_hdr_len + sizeof(struct icmphdr));
        double rtt = (time_received.tv_sec - tv_sent->tv_sec) * 1000.0 +
                     (time_received.tv_usec - tv_sent->tv_usec) / 1000.0;
        
        // Update RTT statistics
        stats->rtt_total += rtt;
        stats->rtt_total_sq += rtt * rtt;
        if (rtt < stats->rtt_min) stats->rtt_min = rtt;
        if (rtt > stats->rtt_max) stats->rtt_max = rtt;

        // NEW: Get the hostname and IP for the output line
        char reply_host[NI_MAXHOST];
        char reply_ip[INET_ADDRSTRLEN];
        perform_reverse_dns(from_addr, from_len, reply_host, sizeof(reply_host));
        inet_ntop(from_addr->ss_family, &(((struct sockaddr_in *)from_addr)->sin_addr), reply_ip, sizeof(reply_ip));
        
        // Print the full, correct line
        printf("%zd bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms\n",
               len - ip_hdr_len,
               reply_host,
               reply_ip,
               ntohs(icmp_hdr->un.echo.sequence),
               ip_hdr->ip_ttl,
               rtt);
    }
}