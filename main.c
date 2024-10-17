#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "config.h"
#include "connection.h"
#include "display.h"
#include "packet_logic.h"
#include "utils.h"

volatile sig_atomic_t stop = 0;

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
    free_connections();

    return EXIT_SUCCESS;
}
