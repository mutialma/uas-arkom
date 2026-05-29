/* ============================================================
 * ids_hybrid.c
 * Versi HYBRID: OpenMP (preprocessing & agregasi) + OpenCL (matching)
 *
 * Pipeline:
 *   [Disk] → load (serial)
 *         → preprocess paralel (OpenMP): normalisasi payload
 *         → pattern matching (OpenCL kernel di GPU)
 *         → agregasi paralel (OpenMP): histogram, statistik IP
 *
 * Compile: gcc -fopenmp -O2 ids_hybrid.c log_loader.c -o ids_hybrid -lOpenCL
 * ============================================================ */
#include "ids_common.h"
#include <omp.h>
#include <ctype.h>

#define CL_TARGET_OPENCL_VERSION 220
#ifdef __APPLE__
  #include <OpenCL/cl.h>
#else
  #include <CL/cl.h>
#endif

#define KERNEL_MAX_PAYLOAD 256
#define KERNEL_MAX_PATTERN 64

extern int load_logs(const char *filename, LogEntry *logs, int max_logs);

#define CHECK_CL(err, msg) do { \
    if ((err) != CL_SUCCESS) { fprintf(stderr,"OpenCL err %d: %s\n",(err),(msg)); exit(1);} \
    } while(0)

static char *read_kernel(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb"); if (!fp) return NULL;
    fseek(fp, 0, SEEK_END); long sz = ftell(fp); fseek(fp, 0, SEEK_SET);
    char *buf = malloc(sz + 1); fread(buf, 1, sz, fp); buf[sz]=0; fclose(fp);
    *out_len = sz; return buf;
}

/* Hash sederhana untuk menghitung frekuensi IP */
typedef struct { char ip[MAX_IP_LEN]; int count; } IpStat;
#define IP_TABLE_SIZE 1024

int main(int argc, char **argv) {
    const char *logfile     = (argc > 1) ? argv[1] : "network_logs.txt";
    const char *kernel_path = (argc > 2) ? argv[2] : "ids_kernel.cl";
    int num_threads         = (argc > 3) ? atoi(argv[3]) : omp_get_max_threads();

    LogEntry *logs = malloc(sizeof(LogEntry) * MAX_LOGS);
    printf("=== IDS Hybrid (OpenMP + OpenCL) ===\n");
    printf("CPU threads : %d\n", num_threads);
    omp_set_num_threads(num_threads);

    int n = load_logs(logfile, logs, MAX_LOGS);
    if (n <= 0) { fprintf(stderr,"Gagal memuat log\n"); return 1; }
    printf("Berhasil memuat %d log dari %s\n\n", n, logfile);

    int P = (int)NUM_PATTERNS;
    char *h_payloads = calloc((size_t)n * KERNEL_MAX_PAYLOAD, 1);
    char *h_patterns = calloc((size_t)P * KERNEL_MAX_PATTERN, 1);
    int  *h_sev      = malloc(sizeof(int) * P);

    /* ---------- TAHAP 1: PREPROCESSING PARALEL (OpenMP) ---------- *
     * Setiap thread menormalisasi payload: case-insensitive lookup
     * dengan menyalin payload apa adanya (di sini kita pertahankan case
     * agar pattern seperti "UNION SELECT" tetap cocok).
     */
    double t_pre = now_sec();
    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        char *dst = h_payloads + i * KERNEL_MAX_PAYLOAD;
        const char *src = logs[i].payload;
        int j;
        for (j = 0; j < KERNEL_MAX_PAYLOAD - 1 && src[j]; j++) dst[j] = src[j];
        dst[j] = '\0';
    }
    t_pre = now_sec() - t_pre;

    for (int p = 0; p < P; p++) {
        strncpy(h_patterns + p * KERNEL_MAX_PATTERN,
                ATTACK_PATTERNS[p].signature, KERNEL_MAX_PATTERN - 1);
        h_sev[p] = ATTACK_PATTERNS[p].severity;
    }

    /* ---------- TAHAP 2: PATTERN MATCHING DI GPU (OpenCL) ---------- */
    cl_int err;
    cl_uint nplat;
    clGetPlatformIDs(0, NULL, &nplat);
    cl_platform_id *plats = malloc(sizeof(cl_platform_id) * nplat);
    clGetPlatformIDs(nplat, plats, NULL);

    cl_device_id device = NULL;
    cl_platform_id plat = NULL;
    cl_device_type dtype = 0;
    for (cl_uint i = 0; i < nplat; i++) {
        if (clGetDeviceIDs(plats[i], CL_DEVICE_TYPE_GPU, 1, &device, NULL) == CL_SUCCESS) {
            plat = plats[i]; dtype = CL_DEVICE_TYPE_GPU; break;
        }
    }
    if (!device) {
        for (cl_uint i = 0; i < nplat; i++)
            if (clGetDeviceIDs(plats[i], CL_DEVICE_TYPE_CPU, 1, &device, NULL) == CL_SUCCESS) {
                plat = plats[i]; dtype = CL_DEVICE_TYPE_CPU; break;
            }
    }
    if (!device) { fprintf(stderr,"OpenCL device tidak ada\n"); return 1; }

    char dn[256] = {0};
    clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(dn), dn, NULL);
    printf("GPU device  : %s (%s)\n\n",
           dn, dtype == CL_DEVICE_TYPE_GPU ? "GPU" : "CPU");

    cl_context ctx = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    cl_command_queue q = clCreateCommandQueueWithProperties(ctx, device, NULL, &err);

    size_t klen;
    char *ksrc = read_kernel(kernel_path, &klen);
    cl_program prog = clCreateProgramWithSource(ctx, 1, (const char**)&ksrc, &klen, &err);
    err = clBuildProgram(prog, 1, &device, "-cl-std=CL1.2", NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t ls; clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &ls);
        char *blog = malloc(ls);
        clGetProgramBuildInfo(prog, device, CL_PROGRAM_BUILD_LOG, ls, blog, NULL);
        fprintf(stderr, "%s\n", blog); return 1;
    }
    cl_kernel kern = clCreateKernel(prog, "detect_attacks", &err);

    cl_mem d_pay = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                  (size_t)n * KERNEL_MAX_PAYLOAD, h_payloads, &err);
    cl_mem d_pat = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                  (size_t)P * KERNEL_MAX_PATTERN, h_patterns, &err);
    cl_mem d_sv  = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                  sizeof(int)*P, h_sev, &err);
    cl_mem d_mt  = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, (size_t)n * P, NULL, &err);
    cl_mem d_th  = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(int)*n, NULL, &err);
    cl_mem d_sl  = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY, sizeof(int)*n, NULL, &err);

    clSetKernelArg(kern, 0, sizeof(cl_mem), &d_pay);
    clSetKernelArg(kern, 1, sizeof(cl_mem), &d_pat);
    clSetKernelArg(kern, 2, sizeof(cl_mem), &d_sv);
    clSetKernelArg(kern, 3, sizeof(int),    &n);
    clSetKernelArg(kern, 4, sizeof(int),    &P);
    clSetKernelArg(kern, 5, sizeof(cl_mem), &d_mt);
    clSetKernelArg(kern, 6, sizeof(cl_mem), &d_th);
    clSetKernelArg(kern, 7, sizeof(cl_mem), &d_sl);

    size_t local = 64;
    size_t global = ((n + local - 1) / local) * local;

    double t_gpu = now_sec();
    clEnqueueNDRangeKernel(q, kern, 1, NULL, &global, &local, 0, NULL, NULL);
    clFinish(q);
    t_gpu = now_sec() - t_gpu;

    unsigned char *h_match = calloc((size_t)n * P, 1);
    int *h_thpl = calloc(n, sizeof(int));
    int *h_slpl = calloc(n, sizeof(int));
    clEnqueueReadBuffer(q, d_mt, CL_TRUE, 0, (size_t)n*P, h_match, 0, NULL, NULL);
    clEnqueueReadBuffer(q, d_th, CL_TRUE, 0, sizeof(int)*n, h_thpl, 0, NULL, NULL);
    clEnqueueReadBuffer(q, d_sl, CL_TRUE, 0, sizeof(int)*n, h_slpl, 0, NULL, NULL);

    /* ---------- TAHAP 3: AGREGASI PARALEL (OpenMP) ---------- */
    int total_threats = 0;
    int sev_hist[5] = {0};
    int pat_hits[NUM_PATTERNS] = {0};

    double t_agg = now_sec();

    #pragma omp parallel
    {
        int loc_sev[5] = {0};
        int loc_pat[NUM_PATTERNS] = {0};

        #pragma omp for reduction(+:total_threats) schedule(static)
        for (int i = 0; i < n; i++) {
            total_threats += h_thpl[i];
            for (int p = 0; p < P; p++) {
                if (h_match[i * P + p]) {
                    loc_pat[p]++;
                    loc_sev[ATTACK_PATTERNS[p].severity]++;
                }
            }
        }

        #pragma omp critical
        {
            for (int s = 0; s < 5; s++) sev_hist[s] += loc_sev[s];
            for (int p = 0; p < P; p++)  pat_hits[p] += loc_pat[p];
        }
    }

    /* Statistik attacker IP (Top-5) — OpenMP atomic */
    IpStat *table = calloc(IP_TABLE_SIZE, sizeof(IpStat));
    #pragma omp parallel for schedule(static)
    for (int i = 0; i < n; i++) {
        if (h_thpl[i] == 0) continue;
        unsigned long h = 5381;
        for (int k = 0; logs[i].src_ip[k]; k++)
            h = ((h << 5) + h) + (unsigned char)logs[i].src_ip[k];
        int slot = (int)(h % IP_TABLE_SIZE);

        for (int probe = 0; probe < IP_TABLE_SIZE; probe++) {
            int idx = (slot + probe) % IP_TABLE_SIZE;
            #pragma omp critical(ip_tab)
            {
                if (table[idx].count == 0) {
                    strncpy(table[idx].ip, logs[i].src_ip, MAX_IP_LEN-1);
                    table[idx].count = h_thpl[i];
                    probe = IP_TABLE_SIZE;
                } else if (strcmp(table[idx].ip, logs[i].src_ip) == 0) {
                    table[idx].count += h_thpl[i];
                    probe = IP_TABLE_SIZE;
                }
            }
        }
    }
    t_agg = now_sec() - t_agg;

    /* Top-5 attacker */
    IpStat top[5] = {0};
    for (int i = 0; i < IP_TABLE_SIZE; i++) {
        if (table[i].count == 0) continue;
        for (int k = 0; k < 5; k++) {
            if (table[i].count > top[k].count) {
                for (int s = 4; s > k; s--) top[s] = top[s-1];
                top[k] = table[i];
                break;
            }
        }
    }

    /* ---------- LAPORAN ---------- */
    printf("--- Hasil Analisis Hybrid ---\n");
    printf("Total threat            : %d\n", total_threats);
    printf("Critical (Lv.4)         : %d\n", sev_hist[4]);
    printf("High     (Lv.3)         : %d\n", sev_hist[3]);
    printf("Medium   (Lv.2)         : %d\n", sev_hist[2]);
    printf("Low      (Lv.1)         : %d\n\n", sev_hist[1]);

    printf("--- Pattern Hit ---\n");
    for (int p = 0; p < P; p++)
        if (pat_hits[p] > 0)
            printf("  [Sev %d] %-25s : %d hit\n",
                   ATTACK_PATTERNS[p].severity, ATTACK_PATTERNS[p].name, pat_hits[p]);

    printf("\n--- Top 5 Attacker IP ---\n");
    for (int k = 0; k < 5; k++)
        if (top[k].count > 0)
            printf("  %d) %-15s  → %d threat\n", k+1, top[k].ip, top[k].count);

    printf("\n--- Breakdown Waktu ---\n");
    printf("Preprocess (OpenMP) : %.4f s\n", t_pre);
    printf("Kernel     (OpenCL) : %.4f s\n", t_gpu);
    printf("Agregasi   (OpenMP) : %.4f s\n", t_agg);
    printf("Total pipeline      : %.4f s\n", t_pre + t_gpu + t_agg);
    printf("Throughput          : %.0f log/detik\n", n / (t_pre + t_gpu + t_agg));

    /* cleanup */
    clReleaseMemObject(d_pay); clReleaseMemObject(d_pat); clReleaseMemObject(d_sv);
    clReleaseMemObject(d_mt);  clReleaseMemObject(d_th);  clReleaseMemObject(d_sl);
    clReleaseKernel(kern); clReleaseProgram(prog);
    clReleaseCommandQueue(q); clReleaseContext(ctx);
    free(plats); free(ksrc);
    free(h_payloads); free(h_patterns); free(h_sev);
    free(h_match); free(h_thpl); free(h_slpl);
    free(table); free(logs);
    return 0;
}
