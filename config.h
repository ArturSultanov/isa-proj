#ifndef CONFIG_H
#define CONFIG_H

/**
 * Defines sorting types for the displayed statistics.
 *
 * SORT_BYTES: Sort by the number of bytes.
 * SORT_PACKETS: Sort by the number of packets.
 */
typedef enum {
    SORT_BYTES,
    SORT_PACKETS
} sort_type_t;


// Holds the program configuration settings.
typedef struct {
    char *interface;
    sort_type_t sort_type; // SORT_BYTES or SORT_PACKETS
    int interval;          // in seconds
} config_t;

/**
 * Global program configuration.
 *
 * Holds the current settings for the program.
 * @see config_t
 */
extern config_t config;

/**
 * Parses command-line arguments to configure the program.
 *
 * @param argc The number of command-line arguments.
 * @param argv The array of command-line arguments.
 * @return 0 on success, or a non-zero value if there is an error in parsing.
 */
int parse_args(int argc, char **argv);


// Prints usage instructions for the program and exits.
void print_usage(char *prog);

#endif
