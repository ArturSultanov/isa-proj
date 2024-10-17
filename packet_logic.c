#include <string.h>
#include <netinet/in.h>
#include <stddef.h>
#include <netinet/ip.h>
// #include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include "packet_logic.h"
#include "connection.h"
#include "config.h"

pcap_t* initialize_pcap(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *session;

    session = pcap_open_live(config.interface, BUFSIZ, 1, 1000, errbuf);

    if (session == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", config.interface, errbuf);
        return NULL;
    }

    return session;
}


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

