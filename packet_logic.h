#ifndef NETWORK_H
#define NETWORK_H

#include <pcap.h>
#include <netinet/ip6.h>

/**
 * Initializes the pcap library for capturing network packets.
 *
 * @return A pointer to the pcap session handle (pcap_t*). Returns NULL if there is an error.
 */
pcap_t* initialize_pcap(void);

/**
 * Parses the IPv6 headers of a captured packet.
 *
 * @param packet Pointer to the captured packet.
 * @param packet_len Length of the captured packet data.
 * @param ip6_hdr Pointer to store a IPv6 header pointer.
 * @param transport_proto Pointer to store the transport protocol.
 * @param transport_header Pointer to a pointer that will be set to the start of the transport layer header.
 * @return 0 if successful, or -1 if an error occurs (e.g., packet too short).
 */
int parse_ipv6_headers(const unsigned char *packet, size_t packet_len, struct ip6_hdr **ip6_hdr, uint8_t *transport_proto, const unsigned char **transport_header);

/**
 * Extracts information from the captured packets.
 *
 * @param header Pointer to the pcap packet header.
 * @param packet Pointer to the packet data.
 */
void packet_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

#endif
