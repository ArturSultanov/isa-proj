#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <getopt.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <ncurses.h>


// Manually define Ethernet types
#define ETHERTYPE_IP 0x0800   // IPv4 Ethernet type
#define ETHERTYPE_IPV6 0x86DD // IPv6 Ethernet type

// This is a global pointer that points to the head of a linked list containing all the current connections.
connection_stats_t *connections = NULL;

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


////////// FUNCTIONS' DECLARATIONS //////////


/**
 * Helper function that print usage hint to stdout
 * @return (void) exit program with EXIT_FAILURE code
 */
void print_usage(char *prog);

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
 * Initialize package capture
 * @param interface capturing interface
 */
pcap_t* initialize_pcap(config_t *config);

/**
 * Compare connetions key to identiry the same connection
 * @param *a first connetion's key pointer
 * @param *b second connection's key pointer
 * @return 1 if the same connection, 0 if different connections
 */
int compare_keys(connection_key_t *a, connection_key_t *b);



////////// FUNCTIONS //////////


config_t parse_args(int argc, char **argv) {
    config_t config;
    config.interface = NULL;
    config.sort_type = SORT_BYTES;  // default sort by bytes
    config.interval = 1;            // default 1 second

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

void print_usage(char *prog) {
    printf("Usage: %s -i <interface> [-s b|p] [-t <interval>]\n", prog);
    exit(EXIT_FAILURE);
}

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

void clear_connections() {
    connection_stats_t *current = connections;
    while (current != NULL) {
        current->rx_bytes = current->tx_bytes = 0;
        current->rx_packets = current->tx_packets = 0;
        current = current->next;
    }
}

void packet_handler(const struct pcap_pkthdr *header, const unsigned char *packet) {
    // Extract EtherType (bytes 12 and 13 in the Ethernet header)
    uint16_t eth_type = (packet[12] << 8) | packet[13];
    eth_type = ntohs(eth_type);

    if (eth_type == 0x0800) {  // IPv4
        // IPv4 header starts at byte 14
        const unsigned char *ip_hdr = packet + 14;
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        // Extract the source and destination IPs from the IPv4 header
        inet_ntop(AF_INET, ip_hdr + 12, src_ip, INET_ADDRSTRLEN);  // Source IP (12-15 bytes)
        inet_ntop(AF_INET, ip_hdr + 16, dst_ip, INET_ADDRSTRLEN);  // Destination IP (16-19 bytes)

        uint8_t protocol = ip_hdr[9];  // Protocol field (byte 9 in the IPv4 header)

        uint16_t src_port = 0, dst_port = 0;
        const char *proto_name = "other";  // Default protocol name

        if (protocol == 6) {  // TCP (protocol number 6)
            const unsigned char *tcp_hdr = ip_hdr + ((ip_hdr[0] & 0x0F) * 4);  // Calculate TCP header offset
            src_port = (tcp_hdr[0] << 8) | tcp_hdr[1];  // TCP source port (bytes 0-1)
            dst_port = (tcp_hdr[2] << 8) | tcp_hdr[3];  // TCP destination port (bytes 2-3)
            proto_name = "tcp";
        } else if (protocol == 17) {  // UDP (protocol number 17)
            const unsigned char *udp_hdr = ip_hdr + ((ip_hdr[0] & 0x0F) * 4);  // Calculate UDP header offset
            src_port = (udp_hdr[0] << 8) | udp_hdr[1];  // UDP source port (bytes 0-1)
            dst_port = (udp_hdr[2] << 8) | udp_hdr[3];  // UDP destination port (bytes 2-3)
            proto_name = "udp";
        }


        // Find or create a connection and update Tx

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
                // This is for Rx: destination is receiving data
                conn->rx_bytes += header->len;  // Increment Rx bytes by the packet length
                conn->rx_packets += 1;
            }
        }

    } else if (eth_type == 0x86DD) {  // IPv6
        // IPv6 header starts at byte 14
        const unsigned char *ip6_hdr = packet + 14;
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];

        // Extract the source and destination IPs from the IPv6 header
        inet_ntop(AF_INET6, ip6_hdr + 8, src_ip, INET6_ADDRSTRLEN);  // Source IP (8-23 bytes)
        inet_ntop(AF_INET6, ip6_hdr + 24, dst_ip, INET6_ADDRSTRLEN); // Destination IP (24-39 bytes)

        uint8_t next_header = ip6_hdr[6];  // Next header field (byte 6 in the IPv6 header)

        uint16_t src_port = 0, dst_port = 0;
        const char *proto_name = "other";

        if (next_header == 6) {  // TCP (next header 6)
            const unsigned char *tcp_hdr = ip6_hdr + 40;  // TCP header starts after the IPv6 header (40 bytes)
            src_port = (tcp_hdr[0] << 8) | tcp_hdr[1];  // TCP source port (bytes 0-1)
            dst_port = (tcp_hdr[2] << 8) | tcp_hdr[3];  // TCP destination port (bytes 2-3)
            proto_name = "tcp";
        } else if (next_header == 17) {  // UDP (next header 17)
            const unsigned char *udp_hdr = ip6_hdr + 40;  // UDP header starts after the IPv6 header (40 bytes)
            src_port = (udp_hdr[0] << 8) | udp_hdr[1];  // UDP source port (bytes 0-1)
            dst_port = (udp_hdr[2] << 8) | udp_hdr[3];  // UDP destination port (bytes 2-3)
            proto_name = "udp";
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

void initialize_ncurses() {
    initscr();              // Start curses mode
    cbreak();               // Disable line buffering
    noecho();               // Don't echo() while we do getch
    curs_set(FALSE);        // Hide the cursor
    nodelay(stdscr, TRUE);  // Non-blocking input
}

void cleanup_ncurses() {
    endwin();
}

typedef struct {
    double value;
    char suffix[4];
} human_readable_t;

human_readable_t format_bytes(uint64_t bytes) {
    human_readable_t hr;
    double b = bytes;
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

human_readable_t format_packets(uint64_t packets) {
    human_readable_t hr;
    double p = packets;
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


int main(int argc, char **argv) {
    config_t config = parse_args(argc, argv);

    printf("Interface: %s\n", config.interface);
    printf("Sort option: %c\n", config.sort_type);
    printf("Interval: %d seconds\n", config.interval);


    return 0;
}
