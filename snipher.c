#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <netinet/in.h>
#include <getopt.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>



int main(int argc, char **argv) {
    int c;

    uint8_t t_protcol = 0;
    char *source_ip = NULL;
    char *dest_ip = NULL;
    uint16_t source_port = 0;
    uint16_t dest_port = 0;

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
                t_protcol = IPPROTO_TCP;
                break;
            case 'u':
                t_protcol = IPPROTO_UDP;
                break;
            case 'p':
                source_port = atoi(optarg);
                break;
            case 'o':
                dest_port = atoi(optarg);
                break;
            case 's':
                source_ip = optarg;
                break;
            case 'd':
                dest_ip = optarg;
                break;
            default:
                abort();
        }
    }

    printf("t_protocol: %d\n", t_protcol);
    printf("source_port: %d\n", source_port);
    printf("dest_port: %d\n", dest_port);
    printf("source_ip: %s\n", source_ip);
    printf("dest_port: %s\n", dest_ip);

    FILE *logfile;
    int sockfd, sockaddr_len;



}


