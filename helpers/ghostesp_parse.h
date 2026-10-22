#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "gt_parse.h"

/**
 * GhostESP adapter.
 *
 * Lets GhostTag run on a board that already has GhostESP: Revival on it (for
 * example the Rabbit-Labs Poltergeist) WITHOUT flashing anything onto the
 * board. GhostTag drives GhostESP's own AirTag scanner ("blescan -a") and reads
 * its human-readable console output, turning it into the same detections the
 * GhostTag companion sketch would have sent as "GT1,..." lines.
 *
 * GhostESP prints a sighting over several lines, for example (v2.x):
 *
 *     [0] AirTag Found (Total: 1)
 *          MAC: aa:bb:cc:dd:ee:ff,
 *          RSSI: -61 dBm (Near),
 *     [0] AirTag RSSI Update: -58 dBm (Near)
 *          MAC: aa:bb:cc:dd:ee:ff
 *
 * and older builds print "AirTag RSSI update: idx 0 MAC aa:.. RSSI -58 dBm" on
 * one line. The parser is a tiny state machine that does not care about the
 * order of the MAC and RSSI lines, so it copes with both.
 *
 * GhostESP repeats the RSSI line for every tag it can still hear at most every
 * 5 s, which is exactly the "still in range" signal the dwell heuristic needs.
 *
 * Kept free of any Flipper dependency so it can be tested on a laptop
 * (test/test_ghostesp_parse.c), like gt_parse.c.
 */

typedef struct {
    bool in_record;
    uint8_t lines_in_record;
    uint8_t type_code;
    bool have_mac;
    uint8_t mac[6];
    bool have_rssi;
    int8_t rssi;
} GhostEspParser;

void ghostesp_parser_reset(GhostEspParser* p);

/**
 * Feed one complete console line (no newline). Returns true and fills @p out
 * when the line completes a sighting.
 */
bool ghostesp_parser_feed(GhostEspParser* p, const char* line, GtDetection* out);
