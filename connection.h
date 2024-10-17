#ifndef CONNECTIONS_H
#define CONNECTIONS_H
#include <netinet/in.h>
#include <stdint.h>

// Represents a unique connection between two endpoints.
typedef struct connection_key {
    char src_ip[INET6_ADDRSTRLEN];
    char src_port[6];
    char dst_ip[INET6_ADDRSTRLEN];
    char dst_port[6];
    char protocol[7];
} connection_key_t;

// Stores statistics for a specific connection.
typedef struct connection_stats {
    connection_key_t key;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t tx_packets;
    struct connection_stats *next;  // Pointer to the next connection in the linked list.
} connection_stats_t;


// Pointer to the head of the linked list of all tracked connections.
extern connection_stats_t *connections;

/**
 * Compares two connection keys.
 *
 * @param a Pointer to the first connection key.
 * @param b Pointer to the second connection key.
 * @return 1 if the keys match (in the same direction),
 * -1 if the keys match but the direction is reversed,
 * 0 if the keys do not match.
 */
int compare_keys(connection_key_t *a, connection_key_t *b);

/**
 * Finds an existing connection or creates a new one.
 * If no match is found, creates a new connection.
 *
 * @param key Pointer to the connection key to search for.
 * @param direction Pointer to an integer that will store the direction.
 * @return A pointer to the connection statistics.
 */
connection_stats_t* get_connection(connection_key_t *key, int *direction);

/**
 * Sorts two connection statistics, depending on the selected sorting type.
 *
 * @param a Pointer to the first connection statistics entry.
 * @param b Pointer to the second connection statistics entry.
 * @return 1 if the second connections has higher score,
 * -1 if the firts connection has higher score,
 * 0 if connections have the same score.
 */
int connection_sort(const void *a, const void *b);

// Clears the statistics for all tracked connections.
void clear_connections(void);

// Frees all memory associated with the tracked connections.
void free_connections(void);

#endif
