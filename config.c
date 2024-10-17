#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "config.h"

config_t config;

int parse_args(int argc, char **argv) {
    config.interface = NULL;
    config.sort_type = SORT_BYTES;  // default sort by bytes
    config.interval = 1;            // default 1 second

    int opt;
    while ((opt = getopt(argc, argv, "i:s:t:")) != -1) {
        switch (opt) {
            case 'i':
                config.interface = optarg;
                break;
            case 's':
                if (strcmp(optarg, "b") == 0)
                    config.sort_type = SORT_BYTES;
                else if (strcmp(optarg, "p") == 0)
                    config.sort_type = SORT_PACKETS;
                else {
                    fprintf(stderr, "Invalid sort type: %s\n", optarg);
                    return -1;
                }
                break;
            case 't':
                config.interval = atoi(optarg);
                if (config.interval <= 0) {
                    fprintf(stderr, "Invalid interval: %s\n", optarg);
                    return -1;
                }
                break;
            default:
                return -1;
        }
    }

    if (config.interface == NULL) {
        fprintf(stderr, "Interface is required.\n");
        return -1;
    }

    return 0;
}

void print_usage(char *prog) {
    printf("Usage: %s -i <interface> [-s b|p] [-t <interval>]\n", prog);
    printf("  -i <interface> : Network interface to capture packets from (e.g., eth0)\n");
    printf("  -s b|p         : Sort by bytes (b) or packets (p). Default is bytes.\n");
    printf("  -t <interval>  : Update interval in seconds. Default is 1 second.\n");
}
