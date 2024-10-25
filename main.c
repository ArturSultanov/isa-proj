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
#include <ncurses.h>

volatile sig_atomic_t stop = 0;

int main(int argc, char **argv) {
    // Parse command-line arguments
    if(parse_args(argc, argv) != 0){
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Initialize ncurses
    initscr();
    cbreak();
    noecho();
    curs_set(FALSE);
    nodelay(stdscr, TRUE);

    // Handle SIGINT for graceful exit
    if (signal(SIGINT, handle_sigint) == SIG_ERR) {
        fprintf(stderr, "Cannot handle SIGINT!\n");
        endwin();
        return EXIT_FAILURE;
    }

    // Initialize pcap
    pcap_t *handle = initialize_pcap();
    if (handle == NULL) {
        endwin();
        return EXIT_FAILURE;
    }

    if (pcap_setnonblock(handle, 1, NULL) == -1) {
        fprintf(stderr, "Failed to set pcap to non-blocking mode: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        endwin();
        return EXIT_FAILURE;
    }

    time_t last_update = time(NULL);

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

        // Reduce CPU usage
        usleep(100000);
    }

    // Cleanup
    pcap_close(handle);
    endwin();
    free_connections();

    return EXIT_SUCCESS;
}
