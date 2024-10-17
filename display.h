#ifndef DISPLAY_H
#define DISPLAY_H

// Represents a readable format for displaying values.
typedef struct {
    double value;   
    char suffix[4]; // K, M, G
} diaplay_t;

// Displays the current network statistics in the terminal.
void display_stats(void);

// Initializes the ncurses library for terminal display.
int initialize_ncurses(void);

// Cleans up the ncurses environment.
void cleanup_ncurses(void);

#endif
