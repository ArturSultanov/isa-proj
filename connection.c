#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "connection.h"
#include "config.h"

connection_stats_t *connections = NULL;

int compare_keys(connection_key_t *a, connection_key_t *b) {
    // Compare protocol first (they must match)
    if (strcmp(a->protocol, b->protocol) != 0) {
        return 0;  // Different
    }

    if (strcmp(a->src_ip, b->src_ip) == 0 && 
        strcmp(a->dst_ip, b->dst_ip) == 0 &&
        strcmp(a->src_port, b->src_port) == 0 &&
        strcmp(a->dst_port, b->dst_port) == 0) {
        return 1;  // Tx direction (matching source and destination)
    }

    if (strcmp(a->src_ip, b->dst_ip) == 0 && 
        strcmp(a->dst_ip, b->src_ip) == 0 &&
        strcmp(a->src_port, b->dst_port) == 0 &&
        strcmp(a->dst_port, b->src_port) == 0) {
        return -1;  // Rx direction (reverse match)
    }

    return 0;  // Different connections
}

connection_stats_t* get_connection(connection_key_t *key, int *direction) {
    connection_stats_t *current = connections;

    // Loop through existing connections to check for a match
    while (current != NULL) {
        int dir = compare_keys(&current->key, key);
        if (dir != 0) {
            *direction = dir;  // Set the direction (1 for Tx, -1 for Rx)
            return current;
        }
        current = current->next;
    }

    // No match found, create a new connection
    *direction = 1; // Default to Tx if it's a new connection

    connection_stats_t *new_conn = malloc(sizeof(connection_stats_t));
    if (!new_conn) {
        perror("malloc");
        return NULL;
    }

    memcpy(&new_conn->key, key, sizeof(connection_key_t));
    new_conn->rx_bytes = new_conn->tx_bytes = 0;
    new_conn->rx_packets = new_conn->tx_packets = 0;
    new_conn->next = connections;
    connections = new_conn;
    return new_conn;
}

int connection_sort(const void *a, const void *b) {
    sort_type_t sort_type = config.sort_type;

    // Cast 'a' and 'b' to pointers to pointers to connection_stats_t
    // Because we are sorting an array of pointers (connection_stats_t*)
    connection_stats_t *conn_a = *(connection_stats_t**)a;
    connection_stats_t *conn_b = *(connection_stats_t**)b;

    if (sort_type == SORT_BYTES) {
        uint64_t total_a = conn_a->rx_bytes + conn_a->tx_bytes;
        uint64_t total_b = conn_b->rx_bytes + conn_b->tx_bytes;
        if (total_b > total_a)
            return 1;
        else if (total_b < total_a)
            return -1;
        else
            return 0;
    } else { // SORT_PACKETS
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

void clear_connections(void) {
    connection_stats_t *current = connections;
    while (current != NULL) {
        current->rx_bytes = current->tx_bytes = 0;
        current->rx_packets = current->tx_packets = 0;
        current = current->next;
    }
}

void free_connections(void) {
    connection_stats_t *current = connections;
    while (current != NULL) {
        connection_stats_t *tmp = current;
        current = current->next;
        free(tmp);
    }
    connections = NULL;
}
