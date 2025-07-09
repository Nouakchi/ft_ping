#include "../includes/ft_ping.h"

uint16_t checksum(void *addr, size_t len) {
  uint16_t *word = addr;
  uint32_t result = 0;
  for (int i = 0; i < len / sizeof(uint16_t); i++) {
    result += *(word + i);
  }
  if (len % 2 == 1) {
    result += *((uint8_t *)addr + len - 1);
  }
  result = (result >> 16) + (result & 0xffff);
  // Carry the previous add.
  result = (result >> 16) + (result & 0xffff);
  return ~result;
}


int DNS_LookUp(t_ping_data *pdata)
{
    struct addrinfo hints;
    struct addrinfo *result;

    // Prepare the hints structure for getaddrinfo
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;       // We will only handle IPv4 for now
    hints.ai_socktype = SOCK_RAW;      // IMPORTANT: Ping uses raw sockets
    hints.ai_protocol = IPPROTO_ICMP;  // IMPORTANT: Specify the ICMP protocol

    // getaddrinfo handles both hostnames and IP addresses automatically
    int status = getaddrinfo(pdata->target_host, NULL, &hints, &result);
    if (status != 0)
    {
        // Provide a much more useful error message to the user
        fprintf(stderr, "ft_ping: %s: %s\n", pdata->target_host, gai_strerror(status));
        return (EXIT_FAILURE);
    }

    // We only need the first result from the linked list
    pdata->addr_info = result;
    memcpy(pdata->addr_info, result, sizeof(*result));

    // Convert the numeric IP address to a string for printing
    struct sockaddr_in *addr_in = (struct sockaddr_in *)pdata->addr_info->ai_addr;
    inet_ntop(AF_INET, &addr_in->sin_addr, pdata->resolved_ip, INET_ADDRSTRLEN);

    freeaddrinfo(result);

    return (EXIT_SUCCESS);
}

void make_ICMP_message(uint8_t **msg, size_t *msg_len)
{
    msg_len = ICMP_MINLEN + sizeof("payload");
    msg = malloc(sizeof(*msg_len));
    struct icmp *imsg = (struct icmp *)*msg;
    imsg->icmp_type = ICMP_ECHO;
    imsg->icmp_code = 0; 
    imsg->icmp_cksum = checksum(*msg, *msg_len);
    imsg->icmp_id = htons(getpid());
    imsg->icmp_seq = htons(1);

    memcpy(imsg->icmp_data, "payload", sizeof("payload"));
}

void interrupt_signal(int data)
{
    (void)data;
    loop = 0;
}

int main(int ac, char *av[])
{
    if (ac < 2)
    {
        // Use fprintf to print errors to stderr
        fprintf(stderr, "ft_ping: usage error: Destination address required\n");
        return (EXIT_FAILURE);
    }

    t_ping_data pdata;
    memset(&pdata, 0, sizeof(pdata));
    pdata.target_host = av[1];

    if (DNS_LookUp(&pdata))
        return (EXIT_FAILURE);

    // Standard PING header output
    printf("PING %s (%s) %ld(%ld) bytes of data.\n",
           pdata.target_host,
           pdata.resolved_ip,
           56L, // Standard payload size
           56L + 28L); // Total size: 56 byte data + 8 byte ICMP header + 20 byte IP header


    // --- CREATION OF THE SOCKET AND START THE PING LOOP --
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sockfd == -1)
        return (fprintf(stderr, "ft_ping: internal error: socket error!\n"), EXIT_FAILURE);
    
    int ttl = 64;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;
    int flag = 1;

    clock_gettime(CLOCK_MONOTONIC, &tfs);

    
    // Set socket options at IP to TTL and value to 64
    if (setsockopt(sockfd, SOL_IP, IP_TTL, &ttl, sizeof(ttl)) != 0) {
        printf("\nSetting socket options to TTL failed!\n");
        return;
    } else {
        printf("\nSocket set to TTL...\n");
    }
    
    // Setting timeout of receive setting
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof(tv_out));
    struct timespec time_start, time_end, tfs, tfe;
    int addr_len, msg_count = 0, msg_received_count = 0;
    struct sockaddr_in r_addr;
    char rbuffer[128];
    long double rtt_msec = 0, total_msec = 0;
    while(loop)
    {
        flag = 1;
        
        // --- Preparing the ICMP header --
        uint8_t *msg;
        size_t  msglen;
        struct sockaddr_in con_addrs;
        make_ICMP_message(&msg, &msglen);
        usleep(PING_SLEEP_RATE);
        // Send packet
        clock_gettime(CLOCK_MONOTONIC, &time_start);
        if (sendto(sockfd, msg, msglen, 0, &con_addrs, sizeof(con_addrs)) <= 0)
        {
            fprintf(stderr, "\nPacket Sending Failed!\n");
            flag = 0;
        }
        // Receive packet
        addr_len = sizeof(r_addr);
        if (recvfrom(sockfd, rbuffer, sizeof(rbuffer), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count > 1) {
            printf("\nPacket receive failed!\n");
        } else {
            clock_gettime(CLOCK_MONOTONIC, &time_end);

            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
            rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

            // If packet was not sent, don't receive
            if (flag) {
                struct icmphdr *recv_hdr = (struct icmphdr *)rbuffer;
                if (!(recv_hdr->type == 0 && recv_hdr->code == 0)) {
                    printf("Error... Packet received with ICMP type %d code %d\n", recv_hdr->type, recv_hdr->code);
                } else {
                    printf("%d bytes from %s (ip: %s) msg_seq = %d ttl = %d rtt = %Lf ms.\n", PACKET_SIZE, rev_host, ping_ip, msg_count, ttl_val, rtt_msec);
                    msg_received_count++;
                }
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0;
    total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;

    printf("\n=== %s ping statistics ===\n", ping_ip);
    printf("%d packets sent, %d packets received, %f%% packet loss. Total time: %Lf ms.\n\n", msg_count, m

    }

    

    return (EXIT_SUCCESS);
}