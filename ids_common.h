/* ============================================================
 * ids_common.h
 * Header bersama untuk Parallel IDS Log Analyzer
 * ============================================================ */
#ifndef IDS_COMMON_H
#define IDS_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LOG_LINE      512
#define MAX_LOGS          200000
#define MAX_PATTERNS      32
#define MAX_PATTERN_LEN   64
#define MAX_IP_LEN        16

/* ---------- Struktur Data ---------- */
typedef struct {
    char  timestamp[32];
    char  src_ip[MAX_IP_LEN];
    char  dst_ip[MAX_IP_LEN];
    int   src_port;
    int   dst_port;
    char  protocol[8];
    int   bytes;
    char  payload[256];
} LogEntry;

typedef struct {
    int   log_id;
    int   pattern_id;
    char  pattern_name[64];
    int   severity;            /* 1=Low, 2=Medium, 3=High, 4=Critical */
    char  src_ip[MAX_IP_LEN];
} Threat;

typedef struct {
    char name[64];
    char signature[MAX_PATTERN_LEN];
    int  severity;
} AttackPattern;

/* ---------- Daftar Pattern Serangan ---------- */
static const AttackPattern ATTACK_PATTERNS[] = {
    {"SQL Injection",        "' OR '1'='1",          4},
    {"SQL Injection UNION",  "UNION SELECT",         4},
    {"XSS Attack",           "<script>",             3},
    {"XSS Alert",            "alert(",               3},
    {"Path Traversal",       "../../",               3},
    {"Command Injection",    ";rm -rf",              4},
    {"Command Injection 2",  "|nc ",                 4},
    {"Brute Force SSH",      "Failed password",      2},
    {"Port Scan",            "SYN_SCAN",             2},
    {"DDoS Flood",           "FLOOD",                4},
    {"Malware C2",           "/cmd.php",             4},
    {"Backdoor",             "/shell.php",           4},
    {"LFI Attack",           "/etc/passwd",          3},
    {"RFI Attack",           "http://evil",          3},
    {"Buffer Overflow",      "AAAAAAAAAAAAAAAA",     4}
};
#define NUM_PATTERNS (sizeof(ATTACK_PATTERNS)/sizeof(AttackPattern))

/* ---------- Utility ---------- */
static inline double now_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

#endif /* IDS_COMMON_H */
