/* ============================================================
 * ids_kernel.cl  -  Kernel OpenCL untuk pattern matching paralel
 * Setiap work-item memproses SATU log; setiap log dicocokkan dengan
 * SELURUH pattern. Output: match_matrix[i*P + p] = 1 jika cocok.
 * ============================================================ */

#define MAX_PAYLOAD 256
#define MAX_PATTERN 64

inline int str_len(__global const char *s, int max_len) {
    int n = 0;
    while (n < max_len && s[n] != '\0') n++;
    return n;
}

inline int str_len_const(__constant const char *s, int max_len) {
    int n = 0;
    while (n < max_len && s[n] != '\0') n++;
    return n;
}

/* Naive substring search — sederhana dan stabil di GPU */
inline int contains(__global const char *text,    int tlen,
                    __constant const char *pat,    int plen) {
    if (plen == 0 || tlen < plen) return 0;
    for (int i = 0; i <= tlen - plen; i++) {
        int j = 0;
        while (j < plen && text[i + j] == pat[j]) j++;
        if (j == plen) return 1;
    }
    return 0;
}

/* ---------- Kernel utama ----------
 * payloads          : array semua payload, fixed-stride MAX_PAYLOAD per log
 * patterns          : array semua pattern, fixed-stride MAX_PATTERN per pattern
 * severities        : tingkat keparahan tiap pattern
 * num_logs          : jumlah log
 * num_patterns      : jumlah pattern
 * match_matrix      : keluaran [num_logs * num_patterns]
 * threat_per_log    : keluaran jumlah threat per log
 * severity_per_log  : keluaran severity maksimum per log
 */
__kernel void detect_attacks(
    __global  const char *payloads,
    __constant const char *patterns,
    __constant const int  *severities,
              const int   num_logs,
              const int   num_patterns,
    __global  uchar       *match_matrix,
    __global  int         *threat_per_log,
    __global  int         *severity_per_log)
{
    int gid = get_global_id(0);
    if (gid >= num_logs) return;

    __global const char *my_payload = payloads + gid * MAX_PAYLOAD;
    int tlen = str_len(my_payload, MAX_PAYLOAD);

    int hits = 0;
    int max_sev = 0;

    for (int p = 0; p < num_patterns; p++) {
        __constant const char *pat = patterns + p * MAX_PATTERN;
        int plen = str_len_const(pat, MAX_PATTERN);

        int found = contains(my_payload, tlen, pat, plen);
        match_matrix[gid * num_patterns + p] = (uchar)found;

        if (found) {
            hits++;
            if (severities[p] > max_sev) max_sev = severities[p];
        }
    }
    threat_per_log[gid]   = hits;
    severity_per_log[gid] = max_sev;
}
