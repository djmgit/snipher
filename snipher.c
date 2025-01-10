#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <getopt.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define exit_with_error(msg) do {perror(msg); exit(EXIT_FAILURE);} while(0)

typedef struct {
    uint8_t t_protocol;
    char *source_ip;
    char *dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
} packet_filter_t;

struct sockaddr_in source_addr, dest_addr;

void log_eth_headers(struct ethhdr *eth, FILE *lf) {
    fprintf(lf, "\nEthernet Header\n");
    fprintf(lf, "\t-Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(lf, "\t-Destination MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(lf, "\t-Protocol : %d\n", eth->h_proto);
}

void log_ip_headers(struct iphdr *ip, FILE *lf) {
    fprintf(lf, "\nIP Header\n");
    
    fprintf(lf, "\t-Version : %d\n", (uint32_t)ip->version);
    fprintf(lf, "\t-Internet Header Length : %d bytes \n", (uint32_t)(ip->ihl * 4));
    fprintf(lf, "\t-Type of Service : %d\n", (uint32_t)ip->tos);
    fprintf(lf, "\t-Total Length : %d\n", ntohs(ip->tot_len));
    fprintf(lf, "\t-Identification : %d\n", (uint32_t)ip->id);
    fprintf(lf, "\t-Time to Live : %d\n", (uint32_t)ip->ttl);
    fprintf(lf, "\t-Protocol : %d\n", (uint32_t)ip->protocol);
    fprintf(lf, "\t-Header Checksum : %d\n", ntohs(ip->check));
    fprintf(lf, "\t-Source IP : %s\n", inet_ntoa(source_addr.sin_addr));
    fprintf(lf, "\t-Destination : %s\n", inet_ntoa(dest_addr.sin_addr));
}

void log_tcp_headers(struct tcphdr *tcp, FILE *lf) {
    fprintf(lf , "\nTCP Header\n");
    fprintf(lf , "\t|-Source Port          : %u\n",ntohs(tcp->source));
   	fprintf(lf , "\t|-Destination Port     : %u\n",ntohs(tcp->dest));
}

void log_udp_headers(struct udphdr *udp, FILE *lf) {
    fprintf(lf , "\tUDP Header\n");
    fprintf(lf , "\t|-Source Port          : %u\n",ntohs(udp->source));
   	fprintf(lf , "\t|-Destination Port     : %u\n",ntohs(udp->dest));
}

void process_packet(uint8_t *buffer, int bufflen, packet_filter_t *packet_filter, FILE *lf) {
    int iphdrlen;

    // process layer 2 header (data link header)
    struct ethhdr *eth = (struct ethhdr*)(buffer);
    log_eth_headers(eth, lf);

    struct iphdr *ip = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    iphdrlen = ip->ihl * 4;

    memset(&source_addr, 0, sizeof(source_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    source_addr.sin_addr.s_addr = ip->saddr;
    dest_addr.sin_addr.s_addr = ip->daddr;

    // TODO: check for ip address filtering
    log_ip_headers(ip, lf);

    uint8_t log_payload = 0;

    if ((ip->protocol == IPPROTO_TCP) && (packet_filter->t_protocol == IPPROTO_TCP || packet_filter->t_protocol == 0)) {
        struct tcphdr *tcp = (struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        // TODO: check for port filtering
        log_tcp_headers(tcp, lf);
        log_payload = 1;
    } else if ((ip->protocol == IPPROTO_UDP) && (packet_filter->t_protocol == IPPROTO_UDP || packet_filter->t_protocol == 0)) {
        struct udphdr *udp = (struct udphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
        log_udp_headers(udp, lf);
        log_payload = 1;
    }

    
}

int main(int argc, char **argv) {
    int c;

    packet_filter_t packet_filter = {0, NULL, NULL, 0, 0};



    struct sockaddr saddr;
    int sockfd, saddr_len, bufflen;

    uint8_t* buffer = (uint8_t*)malloc(65536);
    memset(buffer, 0, 65536);

    FILE *logfile = fopen("snipher_log.txt", "w");
    if (!logfile) {
        exit_with_error("Failed to open log file.");
    }

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        exit_with_error("Failed create raw socket.");
    }
    

    while (1) {
        static struct option long_options[] = {
            {"sip", required_argument, NULL, 's'},
            {"dip", required_argument, NULL, 'd'},
            {"sport", required_argument, NULL, 'p'},
            {"dport", required_argument, NULL, 'o'},
            {"tcp", no_argument, NULL, 't'},
            {"udp", no_argument, NULL, 'u'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "tus:d:p:o:", long_options, NULL);

        if (c == -1) {
            break;
        }

        switch(c) {
            case 't':
                packet_filter.t_protocol = IPPROTO_TCP;
                break;
            case 'u':
                packet_filter.t_protocol = IPPROTO_UDP;
                break;
            case 'p':
                packet_filter.source_port = atoi(optarg);
                break;
            case 'o':
                packet_filter.dest_port = atoi(optarg);
                break;
            case 's':
                packet_filter.source_ip = optarg;
                break;
            case 'd':
                packet_filter.dest_ip = optarg;
                break;
            default:
                abort();
        }
    }

    printf("t_protocol: %d\n", packet_filter.t_protocol);
    printf("source_port: %d\n", packet_filter.source_port);
    printf("dest_port: %d\n", packet_filter.dest_port);
    printf("source_ip: %s\n", packet_filter.source_ip);
    printf("dest_port: %s\n", packet_filter.dest_ip);

    while (1) {
        bufflen = recvfrom(sockfd, buffer, 65536, 0, &saddr, (socklen_t *)&saddr_len);
        if (bufflen < 0) {
            exit_with_error("Failed to read from socket");
        }
        fflush(logfile);
    }



}


