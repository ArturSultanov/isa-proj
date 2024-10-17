#include "utils.h"
#include <string.h>

void handle_sigint(int sig) {
    (void) sig;
    stop = 1;
}

diaplay_t format_bytes(uint64_t bytes) {
    diaplay_t hr;
    double b = (double)bytes;
    if (b >= 1e9) {
        hr.value = b / 1e9;
        strcpy(hr.suffix, "G");
    } else if (b >= 1e6) {
        hr.value = b / 1e6;
        strcpy(hr.suffix, "M");
    } else if (b >= 1e3) {
        hr.value = b / 1e3;
        strcpy(hr.suffix, "K");
    } else {
        hr.value = b;
        strcpy(hr.suffix, " ");
    }
    return hr;
}

diaplay_t format_packets(uint64_t packets) {
    diaplay_t hr;
    double p = (double)packets;
    if (p >= 1e6) {
        hr.value = p / 1e6;
        strcpy(hr.suffix, "M");
    } else if (p >= 1e3) {
        hr.value = p / 1e3;
        strcpy(hr.suffix, "K");
    } else {
        hr.value = p;
        strcpy(hr.suffix, " ");
    }
    return hr;
}