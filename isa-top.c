#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <getopt.h>


typedef enum {
    SORT_BYTES,
    SORT_PACKETS
} sort_type_t;

typedef struct {
    char *interface;
    sort_type_t sort_type;
    int interval; // in seconds
} config_t;

void print_usage(char *prog) {
    printf("Usage: %s -i <interface> [-s b|p] [-t <interval>]\n", prog);
    exit(EXIT_FAILURE);
}

/**
 * Parce the programm arguments
 * @param argc
 * @param argv
    * @param config pointer to config 
 * @see config_t
 * @return 0 if okay, 1 if error
 */
config_t parse_args(int argc, char **argv) {
    config_t config;
    config.interface = NULL;
    config.sort_type = SORT_BYTES;
    config.interval = 1; // default 1 second

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
                    print_usage(argv[0]);
                }
                break;
            case 't':
                config.interval = atoi(optarg);
                if (config.interval <= 0) {
                    fprintf(stderr, "Invalid interval: %s\n", optarg);
                    print_usage(argv[0]);
                }
                break;
            default:
                print_usage(argv[0]);
        }
    }

    if (config.interface == NULL) {
        fprintf(stderr, "Interface is required.\n");
        print_usage(argv[0]);
    }

    return config;
}


pcap_t* initialize_pcap(char *interface) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the session in promiscuous mode
    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(EXIT_FAILURE);
    }

    return handle;
}
            



int main(int argc, char **argv) {
    config_t config = parse_args(argc, argv);

    printf("Interface: %s\n", config.interface);
    printf("Sort option: %c\n", config.sort_type);
    printf("Interval: %d seconds\n", config.interval);


    return 0;
}
