/*
 * Host test for the GhostESP adapter. Build and run from the repo root:
 *
 *   cc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -Ihelpers \
 *      test/test_ghostesp_parse.c helpers/ghostesp_parse.c helpers/ble_signatures.c \
 *      -o /tmp/test_ghostesp && /tmp/test_ghostesp
 *
 * Every input line below is copied from GhostESP: Revival's own glog() format
 * strings (main/scans/ble/airtag_scan.c, device_detect_scan.c and the older
 * main/managers/ble_manager.c), so this checks the real wording.
 */
#include <stdio.h>
#include <string.h>
#include "ghostesp_parse.h"

static int failures = 0;
#define CHECK(cond)                                                      \
    do {                                                                 \
        if(!(cond)) {                                                    \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);       \
            failures++;                                                  \
        }                                                                \
    } while(0)

static const uint8_t MAC1[6] = {0xaa, 0xbb, 0xcc, 0x01, 0x02, 0x03};

/* Feed lines, return how many detections came out; last one in *out. */
static int feed(GhostEspParser* p, const char* const* lines, size_t n, GtDetection* out) {
    int hits = 0;
    for(size_t i = 0; i < n; i++) {
        GtDetection d;
        if(ghostesp_parser_feed(p, lines[i], &d)) {
            *out = d;
            hits++;
        }
    }
    return hits;
}

int main(void) {
    GhostEspParser p;
    GtDetection d;

    /* v2.x discovery: MAC line before RSSI line */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {
            "[0] AirTag Found (Total: 1)",
            "     MAC: aa:bb:cc:01:02:03,",
            "     RSSI: -61 dBm (Near),",
        };
        CHECK(feed(&p, l, 3, &d) == 1);
        CHECK(memcmp(d.mac, MAC1, 6) == 0);
        CHECK(d.rssi == -61);
        CHECK(d.type == TrackerTypeAppleFindMy);
    }

    /* v2.x periodic update: RSSI line before MAC line */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {
            "[0] AirTag RSSI Update: -58 dBm (Near)",
            "     MAC: aa:bb:cc:01:02:03",
        };
        CHECK(feed(&p, l, 2, &d) == 1);
        CHECK(d.rssi == -58);
        CHECK(memcmp(d.mac, MAC1, 6) == 0);
    }

    /* old one-line update: must NOT read "idx 3" as the RSSI */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {"AirTag RSSI update: idx 3 MAC AA:BB:CC:01:02:03 RSSI -72 dBm"};
        CHECK(feed(&p, l, 1, &d) == 1);
        CHECK(d.rssi == -72);
        CHECK(memcmp(d.mac, MAC1, 6) == 0);
    }

    /* old multi-line discovery, with the long payload line afterwards */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {
            "New AirTag found! (Total: 1)",
            "Index: 0",
            "MAC Address: aa:bb:cc:01:02:03",
            "RSSI: -80 dBm",
            "Payload Data: 1E FF 4C 00 12 19 00 ",
        };
        CHECK(feed(&p, l, 5, &d) == 1);
        CHECK(d.rssi == -80);
    }

    /* bledetect first sightings map to the right tracker kinds */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {
            "[4] Tile found",
            "     MAC: 11:22:33:44:55:66",
            "     RSSI: -70 dBm (Medium)",
            "     Variant: Tracker",
            "[5] SmartTag found",
            "     MAC: 11:22:33:44:55:67",
            "     RSSI: -66 dBm (Medium)",
        };
        CHECK(feed(&p, l, 7, &d) == 2);
        CHECK(d.type == TrackerTypeSamsungSmartTag);
        CHECK(d.rssi == -66);
    }

    /* non-tracker bledetect kinds are ignored, and so is their MAC/RSSI */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {
            "[6] AirPods found",
            "     MAC: 11:22:33:44:55:68",
            "     RSSI: -40 dBm (Close)",
        };
        CHECK(feed(&p, l, 3, &d) == 0);
    }

    /* unrelated console chatter, including a WiFi BSSID, produces nothing */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {
            "Starting AirTag Scanner.",
            "BLE device detection started",
            "SSID: home  BSSID: 10:20:30:40:50:60  RSSI: -50",
            "GTALIVE",
            "Unknown command: START",
        };
        CHECK(feed(&p, l, 5, &d) == 0);
    }

    /* an incomplete record is abandoned, not completed by later junk */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {
            "[0] AirTag Found (Total: 1)",
            "something",
            "something else",
            "and more",
            "     MAC: aa:bb:cc:01:02:03,",
            "     RSSI: -61 dBm (Near),",
        };
        CHECK(feed(&p, l, 6, &d) == 0);
    }

    /* hostile values: out-of-range RSSI and malformed MACs are rejected */
    {
        ghostesp_parser_reset(&p);
        const char* l[] = {
            "[0] AirTag RSSI Update: -999 dBm (Near)",
            "     MAC: aa:bb:cc:01:02:03",
        };
        CHECK(feed(&p, l, 2, &d) == 0);

        ghostesp_parser_reset(&p);
        const char* m[] = {
            "[0] AirTag RSSI Update: -50 dBm",
            "     MAC: aa:bb:cc:01:02:03:04",
            "     MAC: zz:bb:cc:01:02:03",
            "",
        };
        CHECK(feed(&p, m, 4, &d) == 0);
    }

    /* a very long line does not read out of bounds (ASan watches this) */
    {
        char big[300];
        memset(big, 'R', sizeof(big) - 1);
        big[sizeof(big) - 1] = '\0';
        ghostesp_parser_reset(&p);
        CHECK(!ghostesp_parser_feed(&p, big, &d));
        CHECK(!ghostesp_parser_feed(&p, "[0] AirTag Found RSSI", &d));
        CHECK(!ghostesp_parser_feed(&p, "RSSI-", &d));
    }

    if(failures == 0) printf("ghostesp_parse: all checks passed\n");
    return failures ? 1 : 0;
}
