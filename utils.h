#ifndef UTILS_H
#define UTILS_H

#include <signal.h>
#include <stdint.h>
#include "display.h"

/**
 * Formats a byte count into a readable format.
 * 
 * @param bytes The bytes to format.
 * @return Structure containing the formatted value and unit suffix.
 */
diaplay_t format_bytes(uint64_t bytes);

/**
 * Formats a packet count into a human-readable format.
 *
 * @param packets The packets to format.
 * @return Structure containing the formatted value and unit suffix.
 */
diaplay_t format_packets(uint64_t packets);

/**
 * Handles the SIGINT signal for a graceful program exit.
 *
 * @param sig The signal (SIGINT).
 */
void handle_sigint(int sig);

// A global flag indicating when the program should stop.
extern volatile sig_atomic_t stop;

#endif
