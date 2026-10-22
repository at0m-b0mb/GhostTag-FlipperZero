#include "ghostesp_parse.h"

#include <string.h>

/* A sighting is at most three lines in any GhostESP version seen so far. A
 * record that is still incomplete after this many lines is abandoned rather
 * than allowed to pick up a MAC or RSSI from some unrelated later output. */
#define MAX_LINES_PER_RECORD 4

static int hex_nibble(char c) {
    if(c >= '0' && c <= '9') return c - '0';
    if(c >= 'a' && c <= 'f') return c - 'a' + 10;
    if(c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Find "hh:hh:hh:hh:hh:hh" anywhere in the line. */
static bool find_mac(const char* line, uint8_t mac[6]) {
    size_t len = strlen(line);
    if(len < 17) return false;
    for(size_t s = 0; s + 17 <= len; s++) {
        bool ok = true;
        uint8_t tmp[6];
        for(int i = 0; i < 6 && ok; i++) {
            const char* b = line + s + i * 3;
            int hi = hex_nibble(b[0]);
            int lo = hex_nibble(b[1]);
            if(hi < 0 || lo < 0) ok = false;
            else if(i < 5 && b[2] != ':') ok = false;
            else tmp[i] = (uint8_t)((hi << 4) | lo);
        }
        /* Reject a longer run such as an IPv6-ish string or a 7-octet value. */
        if(ok && s > 0 && (line[s - 1] == ':' || hex_nibble(line[s - 1]) >= 0)) ok = false;
        if(ok && s + 17 < len && (line[s + 17] == ':' || hex_nibble(line[s + 17]) >= 0)) ok = false;
        if(ok) {
            memcpy(mac, tmp, 6);
            return true;
        }
    }
    return false;
}

/* Find the number after "RSSI", allowing "RSSI: -61", "RSSI -61" and
 * "RSSI Update: -58". Deliberately does NOT skip arbitrary words, because the
 * old one-line format is "RSSI update: idx 3 MAC .. RSSI -58" and skipping
 * "idx" would read the index as a signal strength. */
static bool find_rssi(const char* line, int8_t* out) {
    const char* p = line;
    while((p = strstr(p, "RSSI")) != NULL) {
        const char* q = p + 4;
        if(strncmp(q, " Update", 7) == 0 || strncmp(q, " update", 7) == 0) q += 7;
        while(*q == ':' || *q == ' ') q++;

        bool neg = false;
        if(*q == '-' || *q == '+') {
            neg = (*q == '-');
            q++;
        }
        if(*q >= '0' && *q <= '9') {
            long v = 0;
            int digits = 0;
            while(*q >= '0' && *q <= '9' && digits < 4) {
                v = v * 10 + (*q - '0');
                q++;
                digits++;
            }
            if(neg) v = -v;
            /* Same bound as gt_parse.c: a real receiver cannot report outside it. */
            if(v <= 20 && v >= -128) {
                *out = (int8_t)v;
                return true;
            }
        }
        p += 4;
    }
    return false;
}

/* Which GhostESP line opens a sighting, and what kind of tracker it is.
 * Returns 0 for a line that does not open one. Codes match TrackerType. */
static uint8_t record_start_type(const char* line) {
    /* "blescan -a" (AirTag scanner), all versions, and "bledetect" tracking.
     * GhostESP's AirTag scanner matches the long Find My advertisement, i.e.
     * the "separated" state - the one a planted tag is in. */
    if(strstr(line, "AirTag Found") || strstr(line, "AirTag found") ||
       strstr(line, "AirTag RSSI") || strstr(line, "Tracking AirTag"))
        return 1;

    /* "bledetect" first-sighting lines, if the user started that scan from
     * GhostESP themselves. Only the stalking-capable kinds are taken. */
    if(strstr(line, "] FindMy found")) return 1;
    if(strstr(line, "] Tile found")) return 3;
    if(strstr(line, "] SmartTag found")) return 4;
    if(strstr(line, "] Chipolo found")) return 5;
    return 0;
}

void ghostesp_parser_reset(GhostEspParser* p) {
    memset(p, 0, sizeof(*p));
}

bool ghostesp_parser_feed(GhostEspParser* p, const char* line, GtDetection* out) {
    if(!p || !line || !out) return false;

    uint8_t start = record_start_type(line);
    if(start) {
        ghostesp_parser_reset(p);
        p->in_record = true;
        p->type_code = start;
    } else if(!p->in_record) {
        return false;
    }

    p->lines_in_record++;
    if(!p->have_mac && find_mac(line, p->mac)) p->have_mac = true;
    if(!p->have_rssi && find_rssi(line, &p->rssi)) p->have_rssi = true;

    if(p->have_mac && p->have_rssi) {
        memcpy(out->mac, p->mac, 6);
        out->rssi = p->rssi;
        out->type = tracker_type_from_code(p->type_code);
        out->name[0] = '\0';
        ghostesp_parser_reset(p);
        return true;
    }

    if(p->lines_in_record >= MAX_LINES_PER_RECORD) ghostesp_parser_reset(p);
    return false;
}
