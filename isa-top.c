#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pcap.h>
#include <stdio.h>
#include <getopt.h>
#include <stdint.h>


// Manually define Ethernet types
#define ETHERTYPE_IP 0x0800   // IPv4 Ethernet type
#define ETHERTYPE_IPV6 0x86DD // IPv6 Ethernet type

// This is a global pointer that points to the head of a linked list containing all the current connections.
connection_stats_t *connections = NULL;

//// STRUCTURES /////

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
    printf("Usage: %s -i <interface> [-s b|p] [-t <interval>]\n", prog);
    exit(EXIT_FAILURE);
}

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

#include <stdint.h>

struct ether_header {
    uint8_t ether_dhost[6];  // Destination MAC address
    uint8_t ether_shost[6];  // Source MAC address
    uint16_t ether_type;     // Protocol type (e.g., IPv4 or IPv6)
};

struct ipv4_header {
    uint8_t version_ihl;       // 4 bits version, 4 bits IHL (header length)
    uint8_t type_of_service;   // Type of service
    uint16_t total_length;     // Total length of the IP packet (for byte counting)
    uint16_t identification;   // Identification
    uint16_t flags_offset;     // Flags (3 bits) and fragment offset (13 bits)
    uint8_t ttl;               // Time to live
    uint8_t protocol;          // Protocol (TCP, UDP, ICMP, etc.)
    uint16_t checksum;         // Header checksum
    uint32_t src_ip;           // Source IP address
    uint32_t dest_ip;          // Destination IP address
};

struct tcp_header {
    uint16_t src_port;         // Source port
    uint16_t dest_port;        // Destination port
    uint32_t sequence;         // Sequence number
    uint32_t acknowledgment;   // Acknowledgment number
    uint8_t data_offset;       // Data offset (4 bits)
    uint8_t flags;             // Control flags (e.g., SYN, ACK, FIN, etc.)
    uint16_t window_size;      // Window size
    uint16_t checksum;         // Checksum
    uint16_t urgent_pointer;   // Urgent pointer (if URG flag is set)
};

struct udp_header {
    uint16_t src_port;         // Source port
    uint16_t dest_port;        // Destination port
    uint16_t length;           // Length of the UDP packet
    uint16_t checksum;         // Checksum
};

struct icmp_header {
    uint8_t type;              // ICMP message type
    uint8_t code;              // ICMP message code
    uint16_t checksum;         // Checksum
    uint16_t identifier;       // Identifier (for certain types of ICMP)
    uint16_t sequence_number;  // Sequence number (for certain types of ICMP)
};

struct ipv6_header {
    uint32_t version_class_flow;  // 4 bits version, 8 bits traffic class, 20 bits flow label
    uint16_t payload_length;      // Length of the payload
    uint8_t next_header;          // Next header (TCP, UDP, ICMPv6, etc.)
    uint8_t hop_limit;            // Hop limit (like TTL in IPv4)
    uint8_t src_ip[16];           // Source IP address (128 bits)
    uint8_t dest_ip[16];          // Destination IP address (128 bits)
};

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ether_header *eth = (struct ether_header*) packet;
    uint16_t eth_type = ntohs(eth->ether_type);

    if (eth_type == ETHERTYPE_IP) { // IPv4
        struct ipv4_header *ip_hdr = (struct ipv4_header*)(packet + sizeof(struct ether_header));
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip_hdr->src_ip, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ip_hdr->dest_ip, dst_ip, INET_ADDRSTRLEN);

        uint16_t src_port = 0, dst_port = 0;
        if (ip_hdr->protocol == IPPROTO_TCP) {
            struct tcp_header *tcp = (struct tcp_header*)(packet + sizeof(struct ether_header) + (ip_hdr->version_ihl & 0xF) * 4);
            src_port = ntohs(tcp->src_port);
            dst_port = ntohs(tcp->dest_port);
        } else if (ip_hdr->protocol == IPPROTO_UDP) {
            struct udp_header *udp = (struct udp_header*)(packet + sizeof(struct ether_header) + (ip_hdr->version_ihl & 0xF) * 4);
            src_port = ntohs(udp->src_port);
            dst_port = ntohs(udp->dest_port);
        }
        // Process the connection (src_ip, dst_ip, src_port, dst_port)
    } else if (eth_type == ETHERTYPE_IPV6) { // IPv6
        struct ipv6_header *ip6_hdr = (struct ipv6_header*)(packet + sizeof(struct ether_header));
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, ip6_hdr->src_ip, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, ip6_hdr->dest_ip, dst_ip, INET6_ADDRSTRLEN);

        uint16_t src_port = 0, dst_port = 0;
        if (ip6_hdr->next_header == IPPROTO_TCP) {
            struct tcp_header *tcp = (struct tcp_header*)(packet + sizeof(struct ether_header) + sizeof(struct ipv6_header));
            src_port = ntohs(tcp->src_port);
            dst_port = ntohs(tcp->dest_port);
        } else if (ip6_hdr->next_header == IPPROTO_UDP) {
            struct udp_header *udp = (struct udp_header*)(packet + sizeof(struct ether_header) + sizeof(struct ipv6_header));
            src_port = ntohs(udp->src_port);
            dst_port = ntohs(udp->dest_port);
        }
        // TODO: Process the connection (src_ip, dst_ip, src_port, dst_port) RX/TXS
    }
}




int main(int argc, char **argv) {
    config_t config = parse_args(argc, argv);

    printf("Interface: %s\n", config.interface);
    printf("Sort option: %c\n", config.sort_type);
    printf("Interval: %d seconds\n", config.interval);


    return 0;
}
