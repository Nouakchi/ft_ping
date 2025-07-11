#include "ft_ping.h"

unsigned short checksum(void *b, int len)
{
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
    return (result);
}

void print_summary(char *host, t_ping_stats *stats)
{
    printf("--- %s ping statistics ---\n", host);

    double loss = 0;
    if (stats->packets_sent > 0)
        loss = ((double)(stats->packets_sent - stats->packets_received) / stats->packets_sent) * 100.0;
    
    double total_time_ms = (stats->end_time.tv_sec - stats->start_time.tv_sec) * 1000.0 +
                           (stats->end_time.tv_usec - stats->start_time.tv_usec) / 1000.0;

    printf("%ld packets transmitted, %ld received, %.0f%% packet loss, time %.0fms\n",
           stats->packets_sent, stats->packets_received, loss, total_time_ms);

    if (stats->packets_received > 0)
    {
        double rtt_avg = stats->rtt_total / stats->packets_received;
        double rtt_mdev = sqrt(stats->rtt_total_sq / stats->packets_received - rtt_avg * rtt_avg);
        printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
               stats->rtt_min, rtt_avg, stats->rtt_max, rtt_mdev);
    }
}

void perform_reverse_dns(struct sockaddr_storage *from_addr, socklen_t from_len, char *buffer, size_t len)
{
    if (getnameinfo((struct sockaddr *)from_addr, from_len, buffer, len, NULL, 0, 0) != 0) {
        // If lookup fails, just use the IP address from the reply
        inet_ntop(from_addr->ss_family, 
                  &(((struct sockaddr_in *)from_addr)->sin_addr), 
                  buffer, len);
    }
}

void print_icmp_error_details(struct icmphdr *icmp_hdr)
{
    switch (icmp_hdr->type) 
    {
            case ICMP_DEST_UNREACH:
                // This type has many sub-codes.
                printf("Destination Unreachable: ");
                switch (icmp_hdr->code) {
                    case ICMP_NET_UNREACH:    printf("Net Unreachable\n"); break;
                    case ICMP_HOST_UNREACH:   printf("Host Unreachable\n"); break;
                    case ICMP_PROT_UNREACH:   printf("Protocol Unreachable\n"); break;
                    case ICMP_PORT_UNREACH:   printf("Port Unreachable\n"); break;
                    case ICMP_FRAG_NEEDED:    printf("Fragmentation Needed/DF set\n"); break;
                    case ICMP_SR_FAILED:      printf("Source Route failed\n"); break;
                    case ICMP_NET_UNKNOWN:    printf("Network Unknown\n"); break;
                    case ICMP_HOST_UNKNOWN:   printf("Host Unknown\n"); break;
                    case ICMP_HOST_ISOLATED:  printf("Host Isolated\n"); break;
                    case ICMP_NET_ANO:        printf("Network Prohibited by Admin\n"); break;
                    case ICMP_HOST_ANO:       printf("Host Prohibited by Admin\n"); break;
                    case ICMP_NET_UNR_TOS:    printf("Network Unreachable for TOS\n"); break;
                    case ICMP_HOST_UNR_TOS:   printf("Host Unreachable for TOS\n"); break;
                    case ICMP_PKT_FILTERED:   printf("Packet Filtered (firewall)\n"); break;
                    case ICMP_PREC_VIOLATION: printf("Precedence Violation\n"); break;
                    case ICMP_PREC_CUTOFF:    printf("Precedence Cutoff\n"); break;
                    default:                  printf("Unknown code %d\n", icmp_hdr->code); break;
                }
                break;

            case ICMP_TIME_EXCEEDED:
                // This type has two main codes.
                printf("Time Exceeded: ");
                switch (icmp_hdr->code) {
                    case ICMP_EXC_TTL:      printf("Time to Live exceeded in transit\n"); break;
                    case ICMP_EXC_FRAGTIME: printf("Fragment reassembly time exceeded\n"); break;
                    default:                printf("Unknown code %d\n", icmp_hdr->code); break;
                }
                break;

            case ICMP_REDIRECT:
                // A router is telling us to use a better route.
                printf("Redirect: ");
                switch (icmp_hdr->code) {
                    case ICMP_REDIR_NET:     printf("Redirect for Network\n"); break;
                    case ICMP_REDIR_HOST:    printf("Redirect for Host\n"); break;
                    case ICMP_REDIR_NETTOS:  printf("Redirect for Type of Service and Network\n"); break;
                    case ICMP_REDIR_HOSTTOS: printf("Redirect for Type of Service and Host\n"); break;
                    default:                 printf("Unknown code %d\n", icmp_hdr->code); break;
                }
                // The new gateway IP is stored in the ICMP header data.
                char new_gw_ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &icmp_hdr->un.gateway, new_gw_ip, sizeof(new_gw_ip));
                printf("  New gateway: %s\n", new_gw_ip);
                break;

            case ICMP_SOURCE_QUENCH:
                printf("Source Quench (congestion control)\n");
                break;

            case ICMP_PARAMETERPROB:
                printf("Parameter Problem: Bad IP header\n");
                break;

            default:
                printf("Received unhandled ICMP type %d, code %d\n", icmp_hdr->type, icmp_hdr->code);
                break;
    }
}

double calculate_and_update_rtt(struct timeval *tv_sent, t_ping_stats *stats)
{
    struct timeval time_received;
    gettimeofday(&time_received, NULL);

    double rtt = (time_received.tv_sec - tv_sent->tv_sec) * 1000.0 +
                 (time_received.tv_usec - tv_sent->tv_usec) / 1000.0;
    
    stats->rtt_total += rtt;
    stats->rtt_total_sq += rtt * rtt;
    if (rtt < stats->rtt_min) stats->rtt_min = rtt;
    if (rtt > stats->rtt_max) stats->rtt_max = rtt;

    return rtt;
}

void handle_echo_reply(char *buffer, int ip_hdr_len, struct ip *ip_hdr, struct icmphdr *icmp_hdr, t_ping_data *pdata)
{
    pdata->stats.packets_received++;

    struct timeval *tv_sent = (struct timeval *)(buffer + ip_hdr_len + sizeof(struct icmphdr));
    double rtt = calculate_and_update_rtt(tv_sent, &pdata->stats);

    // Get sender's hostname and IP for the output line
    char reply_host[NI_MAXHOST];
    char reply_ip[INET_ADDRSTRLEN];

    // Note: The source address of the reply comes from the IP header, not a separate parameter.
    // We need to construct a sockaddr_in struct to use our existing helpers.
    struct sockaddr_in from_addr_in;
    memset(&from_addr_in, 0, sizeof(from_addr_in));
    from_addr_in.sin_family = AF_INET;
    from_addr_in.sin_addr = ip_hdr->ip_src;

    perform_reverse_dns((struct sockaddr_storage *)&from_addr_in, sizeof(from_addr_in), reply_host, sizeof(reply_host));
    inet_ntop(AF_INET, &ip_hdr->ip_src, reply_ip, sizeof(reply_ip));
    
    // Print the full, correct line
    printf("%ld bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3f ms\n",
           ntohs(ip_hdr->ip_len) - (long)ip_hdr_len,
           reply_host,
           reply_ip,
           ntohs(icmp_hdr->un.echo.sequence),
           ip_hdr->ip_ttl,
           rtt);
}

void handle_verbose_reply(char *buffer, int ip_hdr_len, struct icmphdr *icmp_hdr, struct sockaddr_storage *from_addr)
{
    char reply_ip[INET_ADDRSTRLEN];
    inet_ntop(from_addr->ss_family, &(((struct sockaddr_in *)from_addr)->sin_addr), reply_ip, sizeof(reply_ip));
    
    // Find the original IP/ICMP headers within the error payload.
    struct ip *orig_ip_hdr = (struct ip *)(buffer + ip_hdr_len + sizeof(struct icmphdr));
    int orig_ip_hdr_len = orig_ip_hdr->ip_hl * 4;
    struct icmphdr *orig_icmp_hdr = (struct icmphdr *)((char *)orig_ip_hdr + orig_ip_hdr_len);

    // Make sure the error is related to one of our sent packets.
    if (ntohs(orig_icmp_hdr->un.echo.id) != getpid()) {
        return; // Not an error for our process.
    }

    printf("From %s: icmp_seq=%d ", reply_ip, ntohs(orig_icmp_hdr->un.echo.sequence));
    
    // Delegate printing the details to our specialized function.
    print_icmp_error_details(icmp_hdr);
}

void process_reply(char *buffer, ssize_t len, struct sockaddr_storage *from_addr, t_ping_data *pdata)
{
    struct ip *ip_hdr = (struct ip *)buffer;
    int ip_hdr_len = ip_hdr->ip_hl * 4;

    // Basic validation: ensure the packet is large enough for IP and ICMP headers.
    if (len < ip_hdr_len + (ssize_t)sizeof(struct icmphdr)) {
        if (pdata->opt_verbose)
            fprintf(stderr, "ft_ping: received packet too short (%zd bytes)\n", len);
        return;
    }

    struct icmphdr *icmp_hdr = (struct icmphdr *)(buffer + ip_hdr_len);

    // Dispatch to the correct handler based on the ICMP type.
    if (icmp_hdr->type == ICMP_ECHOREPLY && ntohs(icmp_hdr->un.echo.id) == getpid())
    {
        write(1, "yes\n", 4);
        handle_echo_reply(buffer, ip_hdr_len, ip_hdr, icmp_hdr, pdata);
    }
    else if (pdata->opt_verbose)
    {
        write(1, "nop\n", 4);
        handle_verbose_reply(buffer, ip_hdr_len, icmp_hdr, from_addr);
    }
}

void parse_arguments(int ac, char *av[], t_ping_data *pdata)
{
    // Initialize options to default values
    pdata->opt_verbose = 0;
    pdata->target_host = NULL;

    for (int i = 1; i < ac; i++)
    {
        if (av[i][0] == '-')
        {
            // It's an option flag
            if (strcmp(av[i], "-v") == 0) {
                pdata->opt_verbose = 1;
            } else if (strcmp(av[i], "-?") == 0) {
                print_usage();
                exit(EXIT_SUCCESS);
            } else {
                fprintf(stderr, "ft_ping: invalid option -- '%s'\n", &av[i][1]);
                print_usage();
                exit(EXIT_FAILURE);
            }
        }
        else
        {
            // It's not a flag, so it must be the destination host
            if (pdata->target_host != NULL) {
                fprintf(stderr, "ft_ping: can only specify one destination host\n");
                exit(EXIT_FAILURE);
            }
            pdata->target_host = av[i];
        }
    }
}

void print_usage(void)
{
    printf("Usage: ft_ping [options] <destination>\n\n");
    printf("Options:\n");
    printf("  -v        verbose output\n");
    printf("  -?        show this help message and exit\n");
}