

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>


///

#include <netinet/ip.h>       // <-- Add this include at the top of your file
#include <netinet/ip_icmp.h>  // <-- You should already have this

///

// Define the Packet Constants
#define PING_PKT_S 64       // ping packet size
#define PORT_NO 0           // automatic port number
#define PING_SLEEP_RATE 1000000  // ping sleep rate (in microseconds)
#define RECV_TIMEOUT 1      // timeout for receiving packets (in seconds)

// Define the Ping Loop
int pingloop = 1;

// Ping packet structure
struct ping_pkt {
    struct icmphdr hdr;
    char msg[PING_PKT_S - sizeof(struct icmphdr)];
};

// Function Declarations
unsigned short checksum(void *b, int len);
void intHandler(int dummy);
char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con);
char *reverse_dns_lookup(char *ip_addr);
void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_dom, char *ping_ip, char *rev_host);

// Calculate the checksum (RFC 1071)
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

// Interrupt handler
void intHandler(int data) {
    (void)data;
    pingloop = 0; 
}

// Perform a DNS lookup
char *dns_lookup(char *addr_host, struct sockaddr_in *addr_con) {
    struct hostent *host_entity;
    char *ip = (char *)malloc(NI_MAXHOST * sizeof(char));

    if ((host_entity = gethostbyname(addr_host)) == NULL) {
        // No IP found for hostname
        return NULL;
    }

    // Fill up address structure
    strcpy(ip, inet_ntoa(*(struct in_addr *)host_entity->h_addr));
    (*addr_con).sin_family = host_entity->h_addrtype;
    (*addr_con).sin_port = htons(PORT_NO);
    (*addr_con).sin_addr.s_addr = *(long *)host_entity->h_addr;

    return ip;
}

// Resolve the reverse lookup of the hostname
char *reverse_dns_lookup(char *ip_addr) {
    struct sockaddr_in temp_addr;
    socklen_t len;
    char buf[NI_MAXHOST], *ret_buf;

    temp_addr.sin_family = AF_INET;
    temp_addr.sin_addr.s_addr = inet_addr(ip_addr);
    len = sizeof(struct sockaddr_in);

    if (getnameinfo((struct sockaddr *)&temp_addr, len, buf, sizeof(buf), NULL, 0, NI_NAMEREQD)) {
        printf("Could not resolve reverse lookup of hostname\n");
        return NULL;
    }

    ret_buf = (char *)malloc((strlen(buf) + 1) * sizeof(char));
    strcpy(ret_buf, buf);
    return ret_buf;
}

// Make a ping request
void send_ping(int ping_sockfd, struct sockaddr_in *ping_addr, char *ping_dom, char *ping_ip, char *rev_host) {
    int ttl_val = 64, msg_count = 0, flag = 1, msg_received_count = 0;
    long unsigned int i = 0;
    unsigned int addr_len;
    char rbuffer[128];
    struct ping_pkt pckt;
    struct sockaddr_in r_addr;
    struct timespec time_start, time_end, tfs, tfe;
    long double rtt_msec = 0, total_msec = 0;
    struct timeval tv_out;
    tv_out.tv_sec = RECV_TIMEOUT;
    tv_out.tv_usec = 0;

    clock_gettime(CLOCK_MONOTONIC, &tfs);

    // Set socket options at IP to TTL and value to 64
    if (setsockopt(ping_sockfd, SOL_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
        printf("\nSetting socket options to TTL failed!\n");
        return;
    }

    // Setting timeout of receive setting
    setsockopt(ping_sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv_out, sizeof tv_out);

    // Send ICMP packet in an infinite loop
    while (pingloop) 
    {
        // Flag to check if packet was sent or not
        flag = 1;

        // Fill the packet
        bzero(&pckt, sizeof(pckt));
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.un.echo.id = getpid();
        for (i = 0; i < sizeof(pckt.msg) - 1; i++)
            pckt.msg[i] = i + '0';

        pckt.msg[i] = 0;
        pckt.hdr.un.echo.sequence = msg_count++;
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

        usleep(PING_SLEEP_RATE);

        // Send packet
        clock_gettime(CLOCK_MONOTONIC, &time_start);
        if (sendto(ping_sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr*)ping_addr, sizeof(*ping_addr)) <= 0) {
            printf("\nPacket Sending Failed!\n");
            flag = 0;
        }

        // Receive packet
        addr_len = sizeof(r_addr);
        if (recvfrom(ping_sockfd, rbuffer, sizeof(rbuffer), 0, (struct sockaddr*)&r_addr, &addr_len) <= 0 && msg_count > 1) {
            printf("\nPacket receive failed!\n");
        } 
        else 
        {
            clock_gettime(CLOCK_MONOTONIC, &time_end);

            double timeElapsed = ((double)(time_end.tv_nsec - time_start.tv_nsec)) / 1000000.0;
            rtt_msec = (time_end.tv_sec - time_start.tv_sec) * 1000.0 + timeElapsed;

            if (flag) {
                // 1. Create a pointer to the beginning of the buffer to read the IP header.
                struct ip *ip_hdr = (struct ip *)rbuffer;

                // 2. The ip_hl field gives the header length in 4-byte words. Multiply by 4
                //    to get the length in bytes. This is usually 20 bytes.
                int ip_header_len = ip_hdr->ip_hl * 4;

                // 3. Now, create a pointer to the ICMP header. It's located in the buffer
                //    right after the IP header.
                struct icmphdr *recv_hdr = (struct icmphdr *)(rbuffer + ip_header_len);

                // 4. Check if the ICMP type is an ECHOREPLY (type 0, code 0)
                if (recv_hdr->type == ICMP_ECHOREPLY && recv_hdr->code == 0) {

                    // 5. IMPORTANT: Check if this reply is for OUR program.
                    //    The ID in the reply should match the process ID we used for sending.
                    if (recv_hdr->un.echo.id == getpid()) {

                        // It's a valid reply meant for us!
                        // The 'bytes from' should be the total ICMP packet size (e.g., 64)
                        printf("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%.3Lf ms\n",
                               PING_PKT_S, // Calculate ICMP packet size
                               ping_dom,
                               ping_ip, 
                               recv_hdr->un.echo.sequence, // Get sequence from the reply
                               ip_hdr->ip_ttl, // Get TTL from the IP header
                               rtt_msec);
                        
                        msg_received_count++;
                    }
                    // else, it's a reply for another ping process on the same machine, so we ignore it.
                
                }
            }
        }
    } 
    clock_gettime(CLOCK_MONOTONIC, &tfe);
    double timeElapsed = ((double)(tfe.tv_nsec - tfs.tv_nsec)) / 1000000.0;
    total_msec = (tfe.tv_sec - tfs.tv_sec) * 1000.0 + timeElapsed;

    printf("\n--- %s ping statistics ---\n", rev_host);
    printf("%d packets transmitted, %d received, %f%% packet loss. time %Lf ms.\n\n", msg_count, msg_received_count, ((msg_count - msg_received_count) / (double)msg_count) * 100.0, total_msec);
}

// Driver Code
int main(int argc, char *argv[]) {
    int sockfd;
    char *ip_addr, *reverse_hostname;
    struct sockaddr_in addr_con;

    if (argc != 2) {
        printf("\nFormat %s <address>\n", argv[0]);
        return 0;
    }

    ip_addr = dns_lookup(argv[1], &addr_con);
    if (ip_addr == NULL) {
        printf("\nDNS lookup failed! Could not resolve hostname!\n");
        return 0;
    }

    reverse_hostname = reverse_dns_lookup(ip_addr);
    printf("PING %s (%s) %ld(%ld) bytes of data.", argv[1], ip_addr, 56L, 56L + 28L);

    // Create a raw socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        printf("\nSocket file descriptor not received!\n");
        return 0;
    } else {
        printf("\nSocket file descriptor %d received\n", sockfd);
    }

    signal(SIGINT, intHandler); // Catching interrupt

    // Send pings continuously
    send_ping(sockfd, &addr_con, reverse_hostname, ip_addr, argv[1]);

    return 0;
}