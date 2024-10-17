#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <getopt.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <signal.h>
#include <ncurses.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>  // For Ethernet header (struct ether_header)
#include <netinet/in.h>    // htons, ntohs for byte order conversions

// ========================
// Data Structures
// ========================

// Sorting types: SORT_BYTES or SORT_PACKETS
typedef enum {
    SORT_BYTES,
    SORT_PACKETS
} sort_type_t;

// Program configuration
typedef struct {
    char *interface;
    sort_type_t sort_type;
    int interval;  // in seconds
} config_t;

// Key that defines unique connection
typedef struct connection_key {
    char src_ip[INET6_ADDRSTRLEN];
    char src_port[6];
    char dst_ip[INET6_ADDRSTRLEN];
    char dst_port[6];
    char protocol[7];
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

// The terminal displayed information
typedef struct {
    double value;
    char suffix[4];
} human_readable_t;

// ========================
// Global Variables
// ========================

// Global pointer to the head of the linked list of connections.
connection_stats_t *connections = NULL;

// Global variable of the program config
config_t config;

// Global flag to indicate when to stop the program
volatile sig_atomic_t stop = 0;

// ========================
// Functions' declarations
// ========================

// Function to parse command-line arguments
int parse_args(int argc, char **argv);

// Function to print usage and exit
void print_usage(char *prog);

// Function to compare two connection keys
int compare_keys(connection_key_t *a, connection_key_t *b);

// Function to find or create a connection
connection_stats_t* get_connection(connection_key_t *key, int* direction);

// Function to clear connection statistics
void clear_connections();

// Function to free all connections
void free_connections_func();

// Function to parse IPv6 headers
int parse_ipv6_headers(const unsigned char *packet, size_t packet_len, struct ip6_hdr **ip6_hdr, uint8_t *transport_proto, const unsigned char **transport_header);

// Packet handler callback
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

// Function to format bytes into human-readable form
human_readable_t format_bytes(uint64_t bytes);

// Function to format packets into human-readable form
human_readable_t format_packets(uint64_t packets);

// Signal handler for SIGINT
void handle_sigint(int sig);

// Function to initialize pcap
pcap_t* initialize_pcap();

// Function to initialize ncurses
int initialize_ncurses();

// Function to cleanup ncurses
void cleanup_ncurses();

// Function to display statistics
void display_stats();

// ========================
// Functions' definitions
// ========================

// ===== CLI arguments parsing =====

// Function to parse command-line arguments
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

// Function to print usage and exit
void print_usage(char *prog) {
    printf("Usage: %s -i <interface> [-s b|p] [-t <interval>]\n", prog);
    printf("  -i <interface> : Network interface to capture packets from (e.g., eth0)\n");
    printf("  -s b|p         : Sort by bytes (b) or packets (p). Default is bytes.\n");
    printf("  -t <interval>  : Update interval in seconds. Default is 1 second.\n");
}

// ===== Connections management =====

// Function to compare two connection keys.
// Returns 1 if identical (Tx), -1 if reverse (Rx), 0 if different
int compare_keys(connection_key_t *a, connection_key_t *b) {
    // Compare protocol first (they must match)
    if (strcmp(a->protocol, b->protocol) != 0) {
        return 0;  // Different
    }

    // Check if the connection is in the Tx direction
    if (strcmp(a->src_ip, b->src_ip) == 0 && 
        strcmp(a->dst_ip, b->dst_ip) == 0 &&
        strcmp(a->src_port, b->src_port) == 0 &&
        strcmp(a->dst_port, b->dst_port) == 0) {
        return 1;  // Tx direction (matching source and destination)
    }

    // Check if the connection is in the Rx direction (reverse match)
    if (strcmp(a->src_ip, b->dst_ip) == 0 && 
        strcmp(a->dst_ip, b->src_ip) == 0 &&
        strcmp(a->src_port, b->dst_port) == 0 &&
        strcmp(a->dst_port, b->src_port) == 0) {
        return -1;  // Rx direction (reverse match)
    }

    return 0;  // Different connections
}

// Function to find or create a connection
connection_stats_t* get_connection(connection_key_t *key, int *direction) {
    connection_stats_t *current = connections;

    // Loop through existing connections to check for a match
    while (current != NULL) {
        int dir = compare_keys(&current->key, key);
        if (dir != 0) {  // If a match is found (Tx or Rx)
            *direction = dir;  // Set the direction (1 for Tx, -1 for Rx)
            return current;    // Return the found connection
        }
        current = current->next;
    }

    // No match found, create a new connection
    *direction = 1; // Default to Tx if it's a new connection

    // Allocate memory for the new connection
    connection_stats_t *new_conn = malloc(sizeof(connection_stats_t));
    if (!new_conn) {
        perror("malloc");
        return NULL;
    }

    // Initialize the new connection
    memcpy(&new_conn->key, key, sizeof(connection_key_t));
    new_conn->rx_bytes = new_conn->tx_bytes = 0;
    new_conn->rx_packets = new_conn->tx_packets = 0;
    new_conn->next = connections;  // Insert the new connection at the head of the list
    connections = new_conn;  // Update the head of the list

    return new_conn;  // Return the newly created connection
}

// Comparator for qsort
int connection_sort(const void *a, const void *b) {
    // The argument 'arg' is cast to the appropriate type, in this case sort_type_t
    sort_type_t sort_type = config.sort_type;

    // Cast 'a' and 'b' to pointers to pointers to connection_stats_t
    // Because we are sorting an array of pointers (connection_stats_t*)
    connection_stats_t *conn_a = *(connection_stats_t**)a;
    connection_stats_t *conn_b = *(connection_stats_t**)b;

    // Compare based on the selected sorting type (bytes or packets)
    if (sort_type == SORT_BYTES) {
        // Compare total bytes (received + transmitted)
        uint64_t total_a = conn_a->rx_bytes + conn_a->tx_bytes;
        uint64_t total_b = conn_b->rx_bytes + conn_b->tx_bytes;
        if (total_b > total_a)
            return 1;    // Return 1 if conn_b should come before conn_a
        else if (total_b < total_a)
            return -1;   // Return -1 if conn_a should come before conn_b
        else
            return 0;    // Return 0 if they are equal
    } else { // SORT_PACKETS
        // Compare total packets (received + transmitted)
        uint64_t total_a = conn_a->rx_packets + conn_a->tx_packets;
        uint64_t total_b = conn_b->rx_packets + conn_b->tx_packets;
        if (total_b > total_a)
            return 1;
        else if (total_b < total_a)
            return -1;
        else
            return 0;
    }
}

// Function to clear connection statistics (reset counts)
void clear_connections() {
    connection_stats_t *current = connections;
    while (current != NULL) {
        current->rx_bytes = current->tx_bytes = 0;
        current->rx_packets = current->tx_packets = 0;
        current = current->next;
    }
}

// Function to free all connections
void free_connections_func() {
    connection_stats_t *current = connections;
    while (current != NULL) {
        connection_stats_t *tmp = current;
        current = current->next;
        free(tmp);
    }
    connections = NULL;
}

// ===== Packets processing =====

// Function to parse IPv6 headers
int parse_ipv6_headers(const unsigned char *packet, size_t packet_len, struct ip6_hdr **ip6_hdr, uint8_t *transport_proto, const unsigned char **transport_header) {
    if (packet_len < sizeof(struct ip6_hdr)) {
        return -1;  // Packet too short
    }

    *ip6_hdr = (struct ip6_hdr*)packet;
    uint8_t next_header = (*ip6_hdr)->ip6_nxt;
    const unsigned char *current_header = packet + sizeof(struct ip6_hdr);
    size_t remaining_len = packet_len - sizeof(struct ip6_hdr);

    // Iterate through extension headers
    while (1) {
        switch (next_header) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS:
            case IPPROTO_FRAGMENT:
            case IPPROTO_AH:
            case IPPROTO_NONE:
                if (remaining_len < 2)
                    return -1;  // Not enough data

                {
                    uint8_t hdr_len = (*(current_header + 1)) * 8 + 8;  // Each unit is 8 bytes
                    if (remaining_len < hdr_len)
                        return -1;

                    next_header = *current_header;
                    current_header += hdr_len;
                    remaining_len -= hdr_len;
                }
                break;
            default:
                // Reached the transport layer
                *transport_proto = next_header;
                *transport_header = current_header;
                return 0;
        }
    }
}

// Packet handler callback
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;
    struct ether_header *eth = (struct ether_header*) packet;  // Catch the raw packet
    uint16_t eth_type = ntohs(eth->ether_type);

    connection_key_t key;  // Create a new connection key
    memset(&key, 0, sizeof(connection_key_t));  // Populate key with zeros

    if (eth_type == ETHERTYPE_IP) {  // IPv4
        if (header->len < sizeof(struct ether_header) + sizeof(struct ip)) {
            // Packet too short for IPv4 header
            return;
        }

        struct ip *ip4_hdr = (struct ip*)(packet + sizeof(struct ether_header));

        // Processing IPv4
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip4_hdr->ip_src), src_ip, INET_ADDRSTRLEN); 
        inet_ntop(AF_INET, &(ip4_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

        // Processing ports
        uint16_t src_port = 0, dst_port = 0;
        char protocol[7] = "other";

        if (ip4_hdr->ip_p == IPPROTO_TCP) {
            if (header->len < sizeof(struct ether_header) + ip4_hdr->ip_hl * 4 + sizeof(struct tcphdr)) {
                // Packet too short for TCP header
                return;
            }
            struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip4_hdr->ip_hl * 4);
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
            strcpy(protocol, "tcp");
        } else if (ip4_hdr->ip_p == IPPROTO_UDP) {
            if (header->len < sizeof(struct ether_header) + ip4_hdr->ip_hl * 4 + sizeof(struct udphdr)) {
                // Packet too short for UDP header
                return;
            }
            struct udphdr *udp = (struct udphdr*)(packet + sizeof(struct ether_header) + ip4_hdr->ip_hl * 4);
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
            strcpy(protocol, "udp");
        } else if (ip4_hdr->ip_p == IPPROTO_ICMP) {
            strcpy(protocol, "icmp");
        }

        // Populate connection key
        strncpy(key.src_ip, src_ip, INET_ADDRSTRLEN);
        snprintf(key.src_port, sizeof(key.src_port), "%u", src_port);
        strncpy(key.dst_ip, dst_ip, INET_ADDRSTRLEN);
        snprintf(key.dst_port, sizeof(key.dst_port), "%u", dst_port);
        strncpy(key.protocol, protocol, sizeof(key.protocol));

    } else if (eth_type == ETHERTYPE_IPV6) { // IPv6
        struct ip6_hdr *ip6_hdr;
        uint8_t transport_proto;
        const unsigned char *transport_header;

        if (parse_ipv6_headers(packet + sizeof(struct ether_header), header->len - sizeof(struct ether_header), &ip6_hdr, &transport_proto, &transport_header) != 0) {
            // Failed to parse IPv6 headers
            return;
        }

        // Ensure there's enough data for the IPv6 header
        if (header->len < sizeof(struct ether_header) + sizeof(struct ip6_hdr)) {
            // Packet too short for IPv6 header
            return;
        }

        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        uint16_t src_port = 0, dst_port = 0;
        char protocol[7] = "other";

        if (transport_proto == IPPROTO_TCP) {
            if (header->len < (transport_header - packet) + sizeof(struct tcphdr)) {
                // Packet too short for TCP header
                return;
            }
            struct tcphdr *tcp = (struct tcphdr*)transport_header;
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
            strcpy(protocol, "tcp");
        } else if (transport_proto == IPPROTO_UDP) {
            if (header->len < (transport_header - packet) + sizeof(struct udphdr)) {
                // Packet too short for UDP header
                return;
            }
            struct udphdr *udp = (struct udphdr*)transport_header;
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
            strcpy(protocol, "udp");
        } else if (transport_proto == IPPROTO_ICMPV6) {
            strcpy(protocol, "icmp6");
        }

        // Populate connection key
        strncpy(key.src_ip, src_ip, INET6_ADDRSTRLEN);
        snprintf(key.src_port, sizeof(key.src_port), "%u", src_port);
        strncpy(key.dst_ip, dst_ip, INET6_ADDRSTRLEN);
        snprintf(key.dst_port, sizeof(key.dst_port), "%u", dst_port);
        strncpy(key.protocol, protocol, sizeof(key.protocol));

    } else {
        // Unsupported EtherType
        return;
    }

    // Retrieve or create the connection statistics
    int direction;
    connection_stats_t *conn = get_connection(&key, &direction);
    if (conn == NULL) {
        // Memory allocation failed
        return;
    }

    // Update statistics based on direction
    if (direction == 1) {
        // Tx direction (outgoing)
        conn->tx_bytes += header->len;
        conn->tx_packets += 1;
    } else if (direction == -1) {
        // Rx direction (incoming)
        conn->rx_bytes += header->len;
        conn->rx_packets += 1;
    }
}

// ===== Display logic =====

void display_stats() {
    // Count connections
    int count = 0;
    connection_stats_t *current = connections;
    while (current != NULL) {
        count++;
        current = current->next;
    }

    if (count == 0) {
        // No connections to display
        clear();
        mvprintw(0, 0, "No connections to display.");
        refresh();
        return;
    }

    // Allocate array for sorting
    connection_stats_t **array = malloc(count * sizeof(connection_stats_t*));
    if (!array) {
        perror("malloc");
        return;
    }

    // Populate array
    current = connections;
    int i = 0;
    while (current != NULL) {
        array[i++] = current;
        current = current->next;
    }

    // Sort the array
    qsort(array, count, sizeof(connection_stats_t*), connection_sort);

    // Clear the screen
    clear();

    // Print headers
    mvprintw(0, 0, "Src IP:port                     Dst IP:port                    Proto    Rx         Tx");
    mvprintw(1, 0, "                                                                        b/s p/s     b/s p/s");

    // Determine how many to display (top 10)
    int display_count = count < 10 ? count : 10;

    // Print top connections
    for (i = 0; i < display_count; i++) {
        connection_stats_t *conn = array[i];
        human_readable_t rx_b = format_bytes(conn->rx_bytes);
        human_readable_t tx_b = format_bytes(conn->tx_bytes);
        human_readable_t rx_p = format_packets(conn->rx_packets);
        human_readable_t tx_p = format_packets(conn->tx_packets);

        // Prepare source and destination strings with port
        char src[INET6_ADDRSTRLEN + 6];
        char dst[INET6_ADDRSTRLEN + 6];

        if (strcmp(conn->key.src_port, "0") != 0)
            snprintf(src, sizeof(src), "%s:%s", conn->key.src_ip, conn->key.src_port);
        else
            snprintf(src, sizeof(src), "%s", conn->key.src_ip);

        if (strcmp(conn->key.dst_port, "0") != 0)
            snprintf(dst, sizeof(dst), "%s:%s", conn->key.dst_ip, conn->key.dst_port);
        else
            snprintf(dst, sizeof(dst), "%s", conn->key.dst_ip);

        // Print the connection info
        mvprintw(2 + i, 0, "%-30s %-30s %-7s %6.1lf%s %5.1lf%s %6.1lf%s %5.1lf%s",
                 src,
                 dst,
                 conn->key.protocol,
                 rx_b.value, rx_b.suffix,
                 rx_p.value, rx_p.suffix,
                 tx_b.value, tx_b.suffix,
                 tx_p.value, tx_p.suffix);
    }

    // Refresh the screen to show changes
    refresh();

    // Free the array
    free(array);
}

// ===== Helper functions =====

// Function to handle SIGINT (Ctrl+C)
void handle_sigint(int sig) {
    (void) sig;
    stop = 1;
}

// Function to initialize pcap
pcap_t* initialize_pcap() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *session;

    session = pcap_open_live(config.interface, BUFSIZ, 1, 1000, errbuf);

    if (session == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", config.interface, errbuf);
        return NULL;
    }

    return session;
}

// Function to initialize ncurses
int initialize_ncurses() {
    initscr();              // Start curses mode
    cbreak();               // Disable line buffering
    noecho();               // Don't echo() while we do getch
    curs_set(FALSE);        // Hide the cursor
    nodelay(stdscr, TRUE);  // Non-blocking input
    return 0;
}

// Cleanup ncurses
void cleanup_ncurses() {
    endwin();               // End curses mode
}

// Function to format bytes into human-readable form
human_readable_t format_bytes(uint64_t bytes) {
    human_readable_t hr;
    double b = (double)bytes;
    if (b >= 1e9) {
        hr.value = b / 1e9;
        strcpy(hr.suffix, "G");
    } else if (b >= 1e6) {
        hr.value = b / 1e6;
        strcpy(hr.suffix, "M");
    } else if (b >= 1e3) {
        hr.value = b / 1e3;
        strcpy(hr.suffix, "K");
    } else {
        hr.value = b;
        strcpy(hr.suffix, " ");
    }
    return hr;
}

// Function to format packets into human-readable form
human_readable_t format_packets(uint64_t packets) {
    human_readable_t hr;
    double p = (double)packets;
    if (p >= 1e6) {
        hr.value = p / 1e6;
        strcpy(hr.suffix, "M");
    } else if (p >= 1e3) {
        hr.value = p / 1e3;
        strcpy(hr.suffix, "K");
    } else {
        hr.value = p;
        strcpy(hr.suffix, " ");
    }
    return hr;
}

// ========================
// Main Function
// ========================

int main(int argc, char **argv) {
    // Parse command-line arguments
    if(parse_args(argc, argv) != 0){
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Initialize ncurses
    if (initialize_ncurses() != 0) {
        return EXIT_FAILURE;
    }

    // Handle SIGINT for graceful exit
    if (signal(SIGINT, handle_sigint) == SIG_ERR) {
        fprintf(stderr, "Cannot handle SIGINT!\n");
        cleanup_ncurses();
        return EXIT_FAILURE;
    }

    // Initialize pcap
    pcap_t *handle = initialize_pcap();
    if (handle == NULL) {
        cleanup_ncurses();
        return EXIT_FAILURE;
    }

    // Set pcap to non-blocking mode
    if (pcap_setnonblock(handle, 1, NULL) == -1) {
        fprintf(stderr, "Failed to set pcap to non-blocking mode: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        cleanup_ncurses();
        return EXIT_FAILURE;
    }

    // Start time tracking
    time_t last_update = time(NULL);

    // Main loop
    while (!stop) {
        // Capture packets
        int ret = pcap_dispatch(handle, -1, packet_handler, NULL);
        if (ret == -1) {
            fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(handle));
            break;
        }

        // Check if it's time to update the display
        time_t current_time = time(NULL);
        if (current_time - last_update >= config.interval) {
            display_stats();
            clear_connections();
            last_update = current_time;
        }

        // Sleep briefly to reduce CPU usage
        usleep(100000); // 100,000 microseconds = 0.1 seconds
    }

    // Cleanup
    pcap_close(handle);
    cleanup_ncurses();
    free_connections_func();

    return EXIT_SUCCESS;
}
