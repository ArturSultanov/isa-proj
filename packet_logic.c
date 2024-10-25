#include <string.h>
#include <netinet/in.h>
#include <stddef.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
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


void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    (void) args;
    struct ether_header *eth = (struct ether_header*) packet;  // Catch the raw packet
    uint16_t eth_type = ntohs(eth->ether_type);

    connection_key_t key;  // Create a new connection key
    memset(&key, 0, sizeof(connection_key_t));  // Populate key with zeros

    if (eth_type == ETHERTYPE_IP) {  // IPv4

        struct ip *ip4_hdr = (struct ip*)(packet + sizeof(struct ether_header));

        // Processing IPv4 pakcet
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip4_hdr->ip_src), src_ip, INET_ADDRSTRLEN); 
        inet_ntop(AF_INET, &(ip4_hdr->ip_dst), dst_ip, INET_ADDRSTRLEN);

        // Processing ports
        uint16_t src_port = 0, dst_port = 0;
        char protocol[7] = "other";

        if (ip4_hdr->ip_p == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + ip4_hdr->ip_hl * 4);
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
            strcpy(protocol, "tcp");
        } else if (ip4_hdr->ip_p == IPPROTO_UDP) {
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

    } else if (eth_type == ETHERTYPE_IPV6) {  // IPv6
        struct ip6_hdr *ip6_hdr = (struct ip6_hdr*)(packet + sizeof(struct ether_header));

        // Processing IPv6 packet
        char src_ip[INET6_ADDRSTRLEN];
        char dst_ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_src), src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &(ip6_hdr->ip6_dst), dst_ip, INET6_ADDRSTRLEN);

        // Processing ports
        uint16_t src_port = 0, dst_port = 0;
        char protocol[7] = "other";

        if (ip6_hdr->ip6_nxt == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            src_port = ntohs(tcp->th_sport);
            dst_port = ntohs(tcp->th_dport);
            strcpy(protocol, "tcp");
        } else if (ip6_hdr->ip6_nxt == IPPROTO_UDP) {
            struct udphdr *udp = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr));
            src_port = ntohs(udp->uh_sport);
            dst_port = ntohs(udp->uh_dport);
            strcpy(protocol, "udp");
        } else if (ip6_hdr->ip6_nxt == IPPROTO_ICMPV6) {
            strcpy(protocol, "icmp6");
        }

        // Populate connection key
        strncpy(key.src_ip, src_ip, INET6_ADDRSTRLEN);
        snprintf(key.src_port, sizeof(key.src_port), "%u", src_port);
        strncpy(key.dst_ip, dst_ip, INET6_ADDRSTRLEN);
        snprintf(key.dst_port, sizeof(key.dst_port), "%u", dst_port);
        strncpy(key.protocol, protocol, sizeof(key.protocol));

    } else {
        return; // Unsupported EtherType
    }

    int direction; // Tx or Rx

    connection_stats_t *conn = get_connection(&key, &direction);

    size_t payload_len = header->len - sizeof(struct ether_header);

    if (direction == 1) {
        // Tx direction (outgoing)
        conn->tx_bytes += payload_len;
        conn->tx_packets += 1;
    } else if (direction == -1) {
        // Rx direction (incoming)
        conn->rx_bytes += payload_len;
        conn->rx_packets += 1;
    }
}

