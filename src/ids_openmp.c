/* ============================================================
 * ids_openmp.c
 * Versi PARALEL menggunakan OpenMP (multi-threading CPU)
 * Compile: gcc -fopenmp -O2 ids_openmp.c log_loader.c -o ids_openmp
 * ============================================================ */
#include "ids_common.h"
#include <omp.h>

extern int load_logs(const char *filename, LogEntry *logs, int max_logs);

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
    int num_threads = (argc > 2) ? atoi(argv[2]) : omp_get_max_threads();

    LogEntry *logs = malloc(sizeof(LogEntry) * MAX_LOGS);
    if (!logs) { fprintf(stderr, "Memori tidak cukup\n"); return 1; }

    printf("=== IDS OpenMP Analyzer ===\n");
    printf("Jumlah thread : %d (max = %d)\n", num_threads, omp_get_max_threads());
    printf("Memuat log dari %s...\n", logfile);

    int n = load_logs(logfile, logs, MAX_LOGS);
    if (n <= 0) { fprintf(stderr, "Gagal memuat log\n"); free(logs); return 1; }
    printf("Berhasil memuat %d log\n\n", n);

    omp_set_num_threads(num_threads);

    /* Akumulator global */
    int  threat_count = 0;
    int  severity_hist[5] = {0};
    int  pattern_hits[NUM_PATTERNS] = {0};
    Threat *threats = malloc(sizeof(Threat) * n * 2);  /* upper bound */
    int  threat_idx = 0;

    double t_start = now_sec();

    /* ---------- PARALEL REGION ---------- *
     * - Loop log dibagi ke beberapa thread (schedule dynamic)
     * - Reduction untuk total threat
     * - Setiap thread punya buffer lokal untuk histogram → digabung di akhir
     * - Critical section hanya saat menulis threat ke array global
     */
    #pragma omp parallel
    {
        int local_severity[5] = {0};
        int local_pattern[NUM_PATTERNS] = {0};

        #pragma omp for schedule(dynamic, 256) reduction(+:threat_count)
        for (int i = 0; i < n; i++) {
            for (int p = 0; p < (int)NUM_PATTERNS; p++) {
                if (contains_pattern(logs[i].payload, ATTACK_PATTERNS[p].signature)) {
                    threat_count++;
                    local_severity[ATTACK_PATTERNS[p].severity]++;
                    local_pattern[p]++;

                    #pragma omp critical(threat_write)
                    {
                        if (threat_idx < n * 2) {
                            Threat *t = &threats[threat_idx++];
                            t->log_id = i;
                            t->pattern_id = p;
                            t->severity = ATTACK_PATTERNS[p].severity;
                            strncpy(t->pattern_name, ATTACK_PATTERNS[p].name, 63);
                            strncpy(t->src_ip, logs[i].src_ip, MAX_IP_LEN-1);
                        }
                    }
                }
            }
        }

        /* Gabungkan hasil lokal ke global */
        #pragma omp critical(merge)
        {
            for (int s = 0; s < 5; s++) severity_hist[s] += local_severity[s];
            for (int p = 0; p < (int)NUM_PATTERNS; p++) pattern_hits[p] += local_pattern[p];
        }
    }

    double t_analyze = now_sec() - t_start;

    printf("--- Hasil Analisis ---\n");
    printf("Total threat terdeteksi : %d\n", threat_count);
    printf("Critical (Lv.4)         : %d\n", severity_hist[4]);
    printf("High     (Lv.3)         : %d\n", severity_hist[3]);
    printf("Medium   (Lv.2)         : %d\n", severity_hist[2]);
    printf("Low      (Lv.1)         : %d\n\n", severity_hist[1]);

    printf("--- Pattern Hit ---\n");
    for (int p = 0; p < (int)NUM_PATTERNS; p++) {
        if (pattern_hits[p] > 0)
            printf("  [Sev %d] %-25s : %d hit\n",
                   ATTACK_PATTERNS[p].severity, ATTACK_PATTERNS[p].name, pattern_hits[p]);
    }

    printf("\n--- Sample Critical Threat ---\n");
    int shown = 0;
    for (int i = 0; i < threat_idx && shown < 5; i++) {
        if (threats[i].severity >= 4) {
            printf("  [!] log#%d  src=%s  → %s\n",
                   threats[i].log_id, threats[i].src_ip, threats[i].pattern_name);
            shown++;
        }
    }

    printf("\n--- Performa OpenMP ---\n");
    printf("Thread aktif    : %d\n", num_threads);
    printf("Waktu analisis  : %.4f detik\n", t_analyze);
    printf("Throughput      : %.0f log/detik\n", n / t_analyze);

    free(threats);
    free(logs);
    return 0;
}
