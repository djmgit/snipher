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

void process_packet(uint8_t *buffer, int bufflen, packet_filter_t *packet_filter, FILE *lf) {
    // process layer 2 header (data link header)
    struct ethhdr *eth = (struct ethhdr*)(buffer);
    fprintf(lf, "\nEthernet Header\n");
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

    printf("t_protocol: %d\n", packet_filter.t_protcol);
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


