/* ============================================================
 * log_loader.c
 * Membaca file log dan mengubahnya menjadi array LogEntry
 * ============================================================ */
#include "ids_common.h"

int load_logs(const char *filename, LogEntry *logs, int max_logs) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen"); return -1; }

    char line[MAX_LOG_LINE];
    int count = 0;

    while (fgets(line, sizeof(line), fp) && count < max_logs) {
        LogEntry *e = &logs[count];
        line[strcspn(line, "\n")] = '\0';

        /* Format: timestamp|src|dst|sport|dport|proto|bytes|payload */
        char *tok = strtok(line, "|"); if (!tok) continue;
        strncpy(e->timestamp, tok, sizeof(e->timestamp)-1);

        tok = strtok(NULL, "|"); if (!tok) continue;
        strncpy(e->src_ip, tok, MAX_IP_LEN-1);

        tok = strtok(NULL, "|"); if (!tok) continue;
        strncpy(e->dst_ip, tok, MAX_IP_LEN-1);

        tok = strtok(NULL, "|"); if (!tok) continue;
        e->src_port = atoi(tok);

        tok = strtok(NULL, "|"); if (!tok) continue;
        e->dst_port = atoi(tok);

        tok = strtok(NULL, "|"); if (!tok) continue;
        strncpy(e->protocol, tok, 7);

        tok = strtok(NULL, "|"); if (!tok) continue;
        e->bytes = atoi(tok);

        tok = strtok(NULL, "|"); if (!tok) continue;
        strncpy(e->payload, tok, sizeof(e->payload)-1);

        count++;
    }
    fclose(fp);
    return count;
}
