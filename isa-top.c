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


// struct ether_header {
//     uint8_t ether_dhost[6];  // Destination MAC address
//     uint8_t ether_shost[6];  // Source MAC address
//     uint16_t ether_type;     // Protocol type (e.g., IPv4 or IPv6)
// };

// struct ipv4_header {
//     uint8_t version_ihl;       // 4 bits version, 4 bits IHL (header length)
//     uint8_t type_of_service;   // Type of service
//     uint16_t total_length;     // Total length of the IP packet (for byte counting)
//     uint16_t identification;   // Identification
//     uint16_t flags_offset;     // Flags (3 bits) and fragment offset (13 bits)
//     uint8_t ttl;               // Time to live
//     uint8_t protocol;          // Protocol (TCP, UDP, ICMP, etc.)
//     uint16_t checksum;         // Header checksum
//     uint32_t src_ip;           // Source IP address
//     uint32_t dest_ip;          // Destination IP address
// };

// struct tcp_header {
//     uint16_t src_port;         // Source port
//     uint16_t dest_port;        // Destination port
//     uint32_t sequence;         // Sequence number
//     uint32_t acknowledgment;   // Acknowledgment number
//     uint8_t data_offset;       // Data offset (4 bits)
//     uint8_t flags;             // Control flags (e.g., SYN, ACK, FIN, etc.)
//     uint16_t window_size;      // Window size
//     uint16_t checksum;         // Checksum
//     uint16_t urgent_pointer;   // Urgent pointer (if URG flag is set)
// };

// struct udp_header {
//     uint16_t src_port;         // Source port
//     uint16_t dest_port;        // Destination port
//     uint16_t length;           // Length of the UDP packet
//     uint16_t checksum;         // Checksum
// };

// struct icmp_header {
//     uint8_t type;              // ICMP message type
//     uint8_t code;              // ICMP message code
//     uint16_t checksum;         // Checksum
//     uint16_t identifier;       // Identifier (for certain types of ICMP)
//     uint16_t sequence_number;  // Sequence number (for certain types of ICMP)
// };

// struct ipv6_header {
//     uint32_t version_class_flow;  // 4 bits version, 8 bits traffic class, 20 bits flow label
//     uint16_t payload_length;      // Length of the payload
//     uint8_t next_header;          // Next header (TCP, UDP, ICMPv6, etc.)
//     uint8_t hop_limit;            // Hop limit (like TTL in IPv4)
//     uint8_t src_ip[16];           // Source IP address (128 bits)
//     uint8_t dest_ip[16];          // Destination IP address (128 bits)
// };

// Manually define Ethernet types
#define ETHERTYPE_IP 0x0800   // IPv4 Ethernet type
#define ETHERTYPE_IPV6 0x86DD // IPv6 Ethernet type
#define ETHERNET_HEADER_SIZE 14

// Sorting types: SORT_BYTES or SORT_PACKETS
typedef enum {
    SORT_BYTES,
    SORT_PACKETS
} sort_type_t;

// Program configuration
typedef struct {
    char *interface;
    sort_type_t sort_type;
    int interval; // in seconds
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

// Global pointer to the head of the linked list containing all the current connections.
connection_stats_t *connections = NULL;

// Global flag to indicate when to stop the program
volatile sig_atomic_t stop = 0;

// Structure to hold human-readable values
typedef struct {
    double value;
    char suffix[4];
} human_readable_t;

// Function Declarations
void print_usage(char *prog);
config_t parse_args(int argc, char **argv);
pcap_t* initialize_pcap(config_t *config);
int compare_keys(connection_key_t *a, connection_key_t *b);
connection_stats_t* get_connection(connection_key_t *key);
void clear_connections();
void handle_sigint(int sig);
void initialize_ncurses();
void cleanup_ncurses();
human_readable_t format_bytes(uint64_t bytes);
human_readable_t format_packets(uint64_t packets);
void display_stats(sort_type_t sort_type);
int compare_connections(const void *a, const void *b);

// Comparator for qsort (global sort_type)
sort_type_t global_sort_type = SORT_BYTES;

#include <ifaddrs.h>
#include <net/if.h>

char local_ipv4[INET_ADDRSTRLEN];
char local_ipv6[INET6_ADDRSTRLEN];

void get_local_ip_addresses(const char *interface) {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

        // Check if the interface matches
        if (strcmp(ifa->ifa_name, interface) != 0)
            continue;

        if (ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, local_ipv4, INET_ADDRSTRLEN);
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)ifa->ifa_addr;
            inet_ntop(AF_INET6, &sa6->sin6_addr, local_ipv6, INET6_ADDRSTRLEN);
        }
    }

    freeifaddrs(ifaddr);
}


const unsigned char* parse_ipv6_headers(const unsigned char *packet, uint8_t *protocol) {
    const unsigned char *ptr = packet;
    const unsigned char *ip6_hdr = ptr;
    uint8_t next_header = ip6_hdr[6];  // Next Header field
    // uint16_t payload_length = (ip6_hdr[4] << 8) | ip6_hdr[5];
    ptr += 40;  // Move past IPv6 header

    // Parse extension headers
    while (1) {
        if (next_header == 6 || next_header == 17) {
            // TCP or UDP
            *protocol = next_header;
            break;
        } else if (next_header == 0 ||  // Hop-by-Hop Options
                   next_header == 43 || // Routing Header
                   next_header == 44 || // Fragment Header
                   next_header == 60 || // Destination Options
                   next_header == 51 || // Authentication Header
                   next_header == 50) { // Encapsulating Security Payload
            // Extension header
            next_header = ptr[0];
            uint16_t hdr_ext_len = (ptr[1] + 1) * 8;
            ptr += hdr_ext_len;
        } else {
            // Unknown or unsupported header
            *protocol = next_header;
            break;
        }
    }

    return ptr;  // Pointer to the transport layer header
}


// Packet Handler
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;
    // Extract EtherType (bytes 12 and 13 in the Ethernet header)
    // Extract EtherType (bytes 12 and 13 in the Ethernet header)
    uint16_t eth_type = (packet[12] << 8) | packet[13];
    eth_type = ntohs(eth_type);

    if (eth_type == ETHERTYPE_IP) {  // IPv4
        const unsigned char *ip_hdr = packet + ETHERNET_HEADER_SIZE;
        struct in_addr src_addr4, dst_addr4;
        memcpy(&src_addr4, ip_hdr + 12, sizeof(struct in_addr));
        memcpy(&dst_addr4, ip_hdr + 16, sizeof(struct in_addr));

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr4, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr4, dst_ip, INET_ADDRSTRLEN);

        uint8_t protocol = ip_hdr[9];  // Protocol field (byte 9)

        uint16_t src_port = 0, dst_port = 0;
        const char *proto_name = "other";

        if (protocol == 6 || protocol == 17) {  // TCP or UDP
            uint8_t ihl = ip_hdr[0] & 0x0F;
            const unsigned char *transport_hdr = ip_hdr + ihl * 4;
            src_port = (transport_hdr[0] << 8) | transport_hdr[1];
            dst_port = (transport_hdr[2] << 8) | transport_hdr[3];
            proto_name = (protocol == 6) ? "tcp" : "udp";
        }

        connection_key_t key;
        strcpy(key.src_ip, src_ip);
        sprintf(key.src_port, "%u", src_port);
        strcpy(key.dst_ip, dst_ip);
        sprintf(key.dst_port, "%u", dst_port);
        strcpy(key.proto, proto_name);

        connection_stats_t *conn = get_connection(&key);
        if (conn) {
            if (strcmp(conn->key.src_ip, key.src_ip) == 0) {
                // This is for Tx: source is sending data
                conn->tx_bytes += header->len;  // Increment Tx bytes by the packet length
                conn->tx_packets += 1;
            } else if (strcmp(conn->key.src_ip, key.dst_ip) == 0) {
                // This is for Rx: destination is sending data
                conn->rx_bytes += header->len;  // Increment Rx bytes by the packet length
                conn->rx_packets += 1;
            }
        }

    } else if (eth_type == ETHERTYPE_IPV6) {  // IPv6
        const unsigned char *ip6_hdr = packet + ETHERNET_HEADER_SIZE;
        struct in6_addr src_addr6, dst_addr6;
        memcpy(&src_addr6, ip6_hdr + 8, sizeof(struct in6_addr));
        memcpy(&dst_addr6, ip6_hdr + 24, sizeof(struct in6_addr));

        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &src_addr6, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &dst_addr6, dst_ip, INET6_ADDRSTRLEN);

        uint8_t protocol;
        const unsigned char *transport_hdr = parse_ipv6_headers(ip6_hdr, &protocol);

        uint16_t src_port = 0, dst_port = 0;
        const char *proto_name = "other";

        if (protocol == 6 || protocol == 17) {  // TCP or UDP
            src_port = (transport_hdr[0] << 8) | transport_hdr[1];
            dst_port = (transport_hdr[2] << 8) | transport_hdr[3];
            proto_name = (protocol == 6) ? "tcp" : "udp";
        }

        connection_key_t key;
        strcpy(key.src_ip, src_ip);
        sprintf(key.src_port, "%u", src_port);
        strcpy(key.dst_ip, dst_ip);
        sprintf(key.dst_port, "%u", dst_port);
        strcpy(key.proto, proto_name);

        connection_stats_t *conn = get_connection(&key);
        if (conn) {
            if (strcmp(conn->key.src_ip, key.src_ip) == 0) {
                // This is for Tx: source is sending data
                conn->tx_bytes += header->len;  // Increment Tx bytes by the packet length
                conn->tx_packets += 1;
            } else if (strcmp(conn->key.src_ip, key.dst_ip) == 0) {
                // This is for Rx: destination is sending data
                conn->rx_bytes += header->len;  // Increment Rx bytes by the packet length
                conn->rx_packets += 1;
            }
        }
    }
}

// Function to compare two connection keys
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
             strcmp(a->dst_port, b->src_port) == 0)));
}

// Function to find or create a connection
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

// Function to clear connection statistics (reset counts)
void clear_connections() {
    connection_stats_t *current = connections;
    while (current != NULL) {
        current->rx_bytes = current->tx_bytes = 0;
        current->rx_packets = current->tx_packets = 0;
        current = current->next;
    }
}

// Signal handler for SIGINT
void handle_sigint(int sig) {
    (void) sig;
    stop = 1;
}

// Initialize ncurses
void initialize_ncurses() {
    initscr();              // Start curses mode
    if (has_colors() == FALSE) {
        endwin();
        fprintf(stderr, "Your terminal does not support color\n");
        exit(1);
    }
    start_color();          // Enable color support
    init_pair(1, COLOR_WHITE, COLOR_BLACK);  // Initialize a default color pair
    cbreak();               // Disable line buffering
    noecho();               // Don't echo() while we do getch
    curs_set(FALSE);        // Hide the cursor
    nodelay(stdscr, TRUE);  // Non-blocking input
}

// Cleanup ncurses
void cleanup_ncurses() {
    endwin();               // End curses mode
}

// Function to format bytes into human-readable format
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
        strcpy(hr.suffix, "B");  // For bytes
    }
    return hr;
}

// Function to format packets into human-readable format
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

// Comparator for qsort
int compare_connections(const void *a, const void *b) {
    connection_stats_t *conn_a = *(connection_stats_t**)a;
    connection_stats_t *conn_b = *(connection_stats_t**)b;

    if (global_sort_type == SORT_BYTES) {
        uint64_t total_a = conn_a->tx_bytes + conn_a->rx_bytes;
        uint64_t total_b = conn_b->tx_bytes + conn_b->rx_bytes;
        if (total_b > total_a)
            return 1;
        else if (total_b < total_a)
            return -1;
        else
            return 0;
    } else { // SORT_PACKETS
        uint64_t total_a = conn_a->tx_packets + conn_a->rx_packets;
        uint64_t total_b = conn_b->tx_packets + conn_b->rx_packets;
        if (total_b > total_a)
            return 1;
        else if (total_b < total_a)
            return -1;
        else
            return 0;
    }
}

// Function to display the top 10 connections using ncurses
void display_stats(sort_type_t sort_type) {
    // Set the global sort type for the comparator
    global_sort_type = sort_type;

    // First, count the number of connections
    int count = 0;
    connection_stats_t *current = connections;
    while (current != NULL && count < 1000) { // Limit to 1000 for safety
        count++;
        current = current->next;
    }

    // Allocate an array to hold pointers to connections
    connection_stats_t **array = malloc(count * sizeof(connection_stats_t*));
    if (!array) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    // Populate the array with connection pointers
    current = connections;
    int i = 0;
    while (current != NULL && i < count) {
        array[i++] = current;
        current = current->next;
    }

    // Sort the array based on the sort_type
    qsort(array, count, sizeof(connection_stats_t*), compare_connections);

    // Clear the screen
    clear();

    // Print header
    attron(COLOR_PAIR(1));
    mvprintw(0, 0, "Src IP:port                     Dst IP:port                    Proto     Rx        Tx");
    mvprintw(1, 0, "                                                                         b/s p/s     b/s p/s");
    attroff(COLOR_PAIR(1));

    // Print top 10 connections
    for (int j = 0; j < 10 && j < count; j++) {
        connection_stats_t *conn = array[j];
        human_readable_t rx_b = format_bytes(conn->rx_bytes);
        human_readable_t tx_b = format_bytes(conn->tx_bytes);
        human_readable_t rx_p = format_packets(conn->rx_packets);
        human_readable_t tx_p = format_packets(conn->tx_packets);

        // Prepare source and destination with port
        char src[INET6_ADDRSTRLEN + 6];
        char dst[INET6_ADDRSTRLEN + 6];

        if (strcmp(conn->key.src_port, "0") != 0) {
            snprintf(src, sizeof(src), "%s:%s", conn->key.src_ip, conn->key.src_port);
        } else {
            snprintf(src, sizeof(src), "%s", conn->key.src_ip);
        }

        if (strcmp(conn->key.dst_port, "0") != 0) {
            snprintf(dst, sizeof(dst), "%s:%s", conn->key.dst_ip, conn->key.dst_port);
        } else {
            snprintf(dst, sizeof(dst), "%s", conn->key.dst_ip);
        }

        // Print the connection stats with one decimal place
        mvprintw(2 + j, 0, "%-30s %-30s %-8s %6.1lf%s %4.1lf%s %6.1lf%s %4.1lf%s",
                 src,
                 dst,
                 conn->key.proto,
                 rx_b.value, rx_b.suffix,
                 rx_p.value, rx_p.suffix,
                 tx_b.value, tx_b.suffix,
                 tx_p.value, tx_p.suffix);
    }

    refresh();  // Refresh the screen to update changes

    // Free the array
    free(array);
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

// Function to print usage and exit
void print_usage(char *prog) {
    printf("Usage: %s -i <interface> [-s b|p] [-t <interval>]\n", prog);
    printf("  -i <interface> : Network interface to capture packets from (e.g., eth0)\n");
    printf("  -s b|p         : Sort by bytes (b) or packets (p). Default is bytes.\n");
    printf("  -t <interval>  : Update interval in seconds. Default is 1 second.\n");
    exit(EXIT_FAILURE);
}

// Function to parse command-line arguments
config_t parse_args(int argc, char **argv) {
    config_t config;
    config.interface = NULL;
    config.sort_type = SORT_BYTES;  // default sort by bytes
    config.interval = 1;            // default 1 second

    int opt;
    while ((opt = getopt(argc, argv, "i:s:t:")) != -1) { // Removed 'p' from options
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

// Function to initialize pcap
pcap_t* initialize_pcap(config_t *config) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *session;

    session = pcap_open_live(config->interface, BUFSIZ, 1, 1000, errbuf);

    if (session == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", config->interface, errbuf);
        exit(EXIT_FAILURE);
    }

    return session;
}

int main(int argc, char **argv) {
    // Parse command-line arguments
    config_t config = parse_args(argc, argv);

    // get_local_ip_addresses(config.interface);

    // Initialize ncurses
    initialize_ncurses();

    // Handle SIGINT for graceful exit
    signal(SIGINT, handle_sigint);

    // Initialize pcap
    pcap_t *handle = initialize_pcap(&config);

    // Set pcap to non-blocking mode
    if (pcap_setnonblock(handle, 1, NULL) == -1) {
        fprintf(stderr, "Failed to set pcap to non-blocking mode: %s\n", pcap_geterr(handle));
        cleanup_ncurses();
        pcap_close(handle);
        exit(EXIT_FAILURE);
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
            display_stats(config.sort_type);
            clear_connections();
            last_update = current_time;
        }

        // Sleep briefly to reduce CPU usage
        usleep(100000); // 100ms
    }

    // Cleanup
    pcap_close(handle);
    cleanup_ncurses();
    free_connections_func();

    return 0;
}
