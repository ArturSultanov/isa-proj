#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <ncurses.h>
#include "display.h"
#include "utils.h"
#include "connection.h"

void display_stats(void) {
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
    mvprintw(0, 0, "Src IP:port                     Dst IP:port                  Protocol    Rx         Tx");
    mvprintw(1, 0, "                                                                        b/s p/s     b/s p/s");

    // Print headers with formatted width
    mvprintw(0, 0, "%-30s %-30s %-7s %5s %15s",
                "Src IP:port", "Dst IP:port", "Proto", "Rx", "Tx");
    mvprintw(1, 0, "%-68s %7s%s %7s%s %7s%s %7s%s", "", "b/s", "", "p/s", "", "b/s", "", "p/s", "");


    // Determine how many to display (top 10)
    int display_count = count < 10 ? count : 10;

    // Print top connections
    for (i = 0; i < display_count; i++) {
        connection_stats_t *conn = array[i];
        diaplay_t rx_b = format_bytes(conn->rx_bytes);
        diaplay_t tx_b = format_bytes(conn->tx_bytes);
        diaplay_t rx_p = format_packets(conn->rx_packets);
        diaplay_t tx_p = format_packets(conn->tx_packets);

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
        mvprintw(2 + i, 0, "%-30s %-30s %-7s %6.1lf%s %6.1lf%s %6.1lf%s %6.1lf%s",
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