/* ============================================================
 * ids_sequential.c
 * Versi SEKUENSIAL (baseline) - tanpa paralelisasi
 * ============================================================ */
#include "ids_common.h"

extern int load_logs(const char *filename, LogEntry *logs, int max_logs);

/* Boyer-Moore Horspool — pencarian substring cepat */
static int contains_pattern(const char *text, const char *pattern) {
    int n = (int)strlen(text);
    int m = (int)strlen(pattern);
    if (m == 0 || n < m) return 0;

    int skip[256];
    for (int i = 0; i < 256; i++) skip[i] = m;
    for (int i = 0; i < m - 1; i++) skip[(unsigned char)pattern[i]] = m - 1 - i;

    int i = 0;
    while (i <= n - m) {
        int j = m - 1;
        while (j >= 0 && text[i+j] == pattern[j]) j--;
        if (j < 0) return 1;
        i += skip[(unsigned char)text[i + m - 1]];
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *logfile = (argc > 1) ? argv[1] : "network_logs.txt";

    LogEntry *logs = malloc(sizeof(LogEntry) * MAX_LOGS);
    if (!logs) { fprintf(stderr, "Memori tidak cukup\n"); return 1; }

    printf("=== IDS Sequential Analyzer ===\n");
    printf("Memuat log dari %s...\n", logfile);

    double t0 = now_sec();
    int n = load_logs(logfile, logs, MAX_LOGS);
    if (n <= 0) { fprintf(stderr, "Gagal memuat log\n"); free(logs); return 1; }
    double t_load = now_sec() - t0;
    printf("Berhasil memuat %d log (%.3fs)\n\n", n, t_load);

    /* Analisis sekuensial */
    int threat_count = 0;
    int severity_hist[5] = {0};
    int pattern_hits[NUM_PATTERNS] = {0};

    double t_start = now_sec();
    for (int i = 0; i < n; i++) {
        for (int p = 0; p < (int)NUM_PATTERNS; p++) {
            if (contains_pattern(logs[i].payload, ATTACK_PATTERNS[p].signature)) {
                threat_count++;
                severity_hist[ATTACK_PATTERNS[p].severity]++;
                pattern_hits[p]++;
            }
        }
    }
    double t_analyze = now_sec() - t_start;

    printf("--- Hasil Analisis ---\n");
    printf("Total threat terdeteksi : %d\n", threat_count);
    printf("Critical (Lv.4)         : %d\n", severity_hist[4]);
    printf("High     (Lv.3)         : %d\n", severity_hist[3]);
    printf("Medium   (Lv.2)         : %d\n", severity_hist[2]);
    printf("Low      (Lv.1)         : %d\n\n", severity_hist[1]);

    printf("--- Top Pattern ---\n");
    for (int p = 0; p < (int)NUM_PATTERNS; p++) {
        if (pattern_hits[p] > 0)
            printf("  [%2d] %-25s : %d hit\n",
                   ATTACK_PATTERNS[p].severity, ATTACK_PATTERNS[p].name, pattern_hits[p]);
    }

    printf("\n--- Performa ---\n");
    printf("Waktu analisis : %.4f detik\n", t_analyze);
    printf("Throughput     : %.0f log/detik\n", n / t_analyze);

    free(logs);
    return 0;
}
