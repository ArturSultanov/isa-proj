#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <getopt.h>
#include <stdint.h>

//// STRUCTURES /////

// Sorting types: SORT_BYTES or SORT_PACKETS
typedef enum {
    SORT_BYTES,
    SORT_PACKETS
} sort_type_t;

// Sorting types: SORT_BYTES or SORT_PACKETS
typedef enum {
    DISABLED,
    ENABLED
} promisc_mode_t;


// Program configuration
typedef struct {
    char *interface;
    sort_type_t sort_type;
    int interval; // in seconds
    promisc_mode_t promisc_mode;
} config_t;

// Key that defines unique connection
typedef struct connection_key {
    char src_ip[INET6_ADDRSTRLEN];
    char src_port[6];
    char dst_ip[INET6_ADDRSTRLEN];
    char dst_port[6];
    char proto[6];
} connection_key_t;

// The statistics of the connection per key
typedef struct connection_stats {
    connection_key_t key;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    struct connection_stats *next;
} connection_stats_t;

// This is a global pointer that points to the head of a linked list containing all the current connections.
connection_stats_t *connections = NULL;


///// FUNCTIONS' DECLARATIONS /////


/**
 * Parce the programm arguments
 * @param argc
 * @param argv
 * @param config pointer to config 
 * @see config_t
 * @return 0 if okay, 1 if error
 */
config_t parse_args(int argc, char **argv);

/**
 * Helper function that print usage hint to stdout
 * @return (void) exit program with EXIT_FAILURE code
 */
void print_usage(char *prog);

/**
 * Initialize package capture
 * @param interface capturing interface
 */
pcap_t* initialize_pcap(config_t *config);


//// FUNCTIONS ////

// CLI Arguments parsing

void print_usage(char *prog) {
    printf("Usage: %s -i <interface> [-s b|p] [-t <interval>] [-p <promisc mode>]\n", prog);
    exit(EXIT_FAILURE);
}

config_t parse_args(int argc, char **argv) {
    config_t config;
    config.interface = NULL;
    config.sort_type = SORT_BYTES;  // default sort by bytes
    config.interval = 1;            // default 1 second
    config.promisc_mode = DISABLED; // default disabled - 0

    int opt;
    while ((opt = getopt(argc, argv, "i:s:t:p")) != -1) {
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
            case 'p':
                if (strcmp(optarg, "e") == 0)
                    config.promisc_mode = ENABLED;
                else if (strcmp(optarg, "d") == 0)
                    config.promisc_mode = DISABLED;
                else {
                    fprintf(stderr, "Invalid promisc mode: %s\n", optarg);
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


pcap_t* initialize_pcap(config_t *config) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *session;

    session = pcap_open_live(config->interface, BUFSIZ, config->promisc_mode, 1000, errbuf);

    if (session == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", config->interface, errbuf);
        exit(EXIT_FAILURE);
    }

    return session;
}


int compare_keys(connection_key_t *a, connection_key_t *b) {
    return (strcmp(a->proto, b->proto) == 0 &&          // protocol
          ((strcmp(a->src_ip, b->src_ip) == 0 &&        // Tx
            strcmp(a->dst_ip, b->dst_ip) == 0 &&
            strcmp(a->src_port, b->src_port) == 0 &&
            strcmp(a->dst_port, b->dst_port) == 0) 
            ||
           (strcmp(a->src_ip, b->dst_ip) == 0 &&        // Rx
            strcmp(a->dst_ip, b->src_ip) == 0 &&
            strcmp(a->src_port, b->dst_port) == 0 &&
            strcmp(a->dst_port, b->src_port) == 0)))
}

connection_stats_t* get_connection(connection_key_t *key) {
    connection_stats_t *current = connections;
    while (current != NULL) {
        if (compare_keys(&current->key, key))
            return current;
        current = current->next;
    }

    // Create new connection
    connection_stats_t *new_conn = malloc(sizeof(connection_stats_t));
    if (!new_conn) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    memcpy(&new_conn->key, key, sizeof(connection_key_t));
    new_conn->rx_bytes = new_conn->tx_bytes = 0;
    new_conn->rx_packets = new_conn->tx_packets = 0;
    new_conn->next = connections;
    connections = new_conn;
    return new_conn;
}

void clear_connections() {
    connection_stats_t *current = connections;
    while (current != NULL) {
        current->rx_bytes = current->tx_bytes = 0;
        current->rx_packets = current->tx_packets = 0;
        current = current->next;
    }
}





int main(int argc, char **argv) {
    config_t config = parse_args(argc, argv);

    printf("Interface: %s\n", config.interface);
    printf("Sort option: %c\n", config.sort_type);
    printf("Interval: %d seconds\n", config.interval);


    return 0;
}
