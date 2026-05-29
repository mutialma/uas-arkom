/* ============================================================
 * ids_opencl.c
 * Versi PARALEL menggunakan OpenCL (GPU / heterogeneous compute)
 * Compile: gcc -O2 ids_opencl.c log_loader.c -o ids_opencl -lOpenCL
 * ============================================================ */
#include "ids_common.h"

#define CL_TARGET_OPENCL_VERSION 220
#ifdef __APPLE__
  #include <OpenCL/cl.h>
#else
  #include <CL/cl.h>
#endif

#define KERNEL_MAX_PAYLOAD 256
#define KERNEL_MAX_PATTERN 64

extern int load_logs(const char *filename, LogEntry *logs, int max_logs);

static char *read_kernel(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) { perror("fopen kernel"); return NULL; }
    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc(sz + 1);
    fread(buf, 1, sz, fp);
    buf[sz] = '\0';
    fclose(fp);
    *out_len = (size_t)sz;
    return buf;
}

#define CHECK_CL(err, msg) do { \
    if ((err) != CL_SUCCESS) { \
        fprintf(stderr, "OpenCL error %d: %s\n", (err), (msg)); \
        exit(1); \
    } } while (0)

int main(int argc, char **argv) {
    const char *logfile    = (argc > 1) ? argv[1] : "network_logs.txt";
    const char *kernel_path = (argc > 2) ? argv[2] : "ids_kernel.cl";

    LogEntry *logs = malloc(sizeof(LogEntry) * MAX_LOGS);
    if (!logs) { fprintf(stderr, "Memori tidak cukup\n"); return 1; }

    printf("=== IDS OpenCL (GPU) Analyzer ===\n");
    printf("Memuat log dari %s...\n", logfile);

    int n = load_logs(logfile, logs, MAX_LOGS);
    if (n <= 0) { fprintf(stderr, "Gagal memuat log\n"); free(logs); return 1; }
    printf("Berhasil memuat %d log\n\n", n);

    int P = (int)NUM_PATTERNS;

    /* ---------- Persiapan buffer host ---------- */
    /* Payload diratakan menjadi array besar dengan stride tetap */
    char *h_payloads = calloc((size_t)n * KERNEL_MAX_PAYLOAD, 1);
    char *h_patterns = calloc((size_t)P * KERNEL_MAX_PATTERN, 1);
    int  *h_sev      = malloc(sizeof(int) * P);

    for (int i = 0; i < n; i++)
        strncpy(h_payloads + i * KERNEL_MAX_PAYLOAD, logs[i].payload, KERNEL_MAX_PAYLOAD - 1);

    for (int p = 0; p < P; p++) {
        strncpy(h_patterns + p * KERNEL_MAX_PATTERN, ATTACK_PATTERNS[p].signature, KERNEL_MAX_PATTERN - 1);
        h_sev[p] = ATTACK_PATTERNS[p].severity;
    }

    unsigned char *h_match  = calloc((size_t)n * P, 1);
    int *h_threats_per_log  = calloc(n, sizeof(int));
    int *h_sev_per_log      = calloc(n, sizeof(int));

    /* ---------- Setup OpenCL ---------- */
    cl_int err;
    cl_uint num_platforms = 0;
    err = clGetPlatformIDs(0, NULL, &num_platforms);
    if (err != CL_SUCCESS || num_platforms == 0) {
        fprintf(stderr, "Tidak ada OpenCL platform terdeteksi.\n");
        return 1;
    }
    cl_platform_id *platforms = malloc(sizeof(cl_platform_id) * num_platforms);
    clGetPlatformIDs(num_platforms, platforms, NULL);

    cl_device_id   device   = NULL;
    cl_platform_id platform = NULL;
    cl_device_type chosen_type = 0;

    /* Pilih GPU jika ada, kalau tidak CPU */
    for (cl_uint i = 0; i < num_platforms; i++) {
        if (clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_GPU, 1, &device, NULL) == CL_SUCCESS) {
            platform = platforms[i]; chosen_type = CL_DEVICE_TYPE_GPU; break;
        }
    }
    if (!device) {
        for (cl_uint i = 0; i < num_platforms; i++) {
            if (clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_CPU, 1, &device, NULL) == CL_SUCCESS) {
                platform = platforms[i]; chosen_type = CL_DEVICE_TYPE_CPU; break;
            }
        }
    }
    if (!device) { fprintf(stderr, "Tidak ada device GPU/CPU OpenCL.\n"); return 1; }

    char dev_name[256] = {0};
    clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(dev_name), dev_name, NULL);
    printf("Device aktif : %s (%s)\n\n",
           dev_name, chosen_type == CL_DEVICE_TYPE_GPU ? "GPU" : "CPU");

    cl_context context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
    CHECK_CL(err, "clCreateContext");

    cl_command_queue queue = clCreateCommandQueueWithProperties(context, device, NULL, &err);
    CHECK_CL(err, "clCreateCommandQueue");

    /* ---------- Build kernel ---------- */
    size_t src_len;
    char *src = read_kernel(kernel_path, &src_len);
    if (!src) return 1;

    cl_program program = clCreateProgramWithSource(context, 1,
                                                   (const char **)&src, &src_len, &err);
    CHECK_CL(err, "clCreateProgramWithSource");

    err = clBuildProgram(program, 1, &device, "-cl-std=CL1.2", NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_size;
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        char *blog = malloc(log_size);
        clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, blog, NULL);
        fprintf(stderr, "Build log:\n%s\n", blog);
        free(blog);
        return 1;
    }

    cl_kernel kernel = clCreateKernel(program, "detect_attacks", &err);
    CHECK_CL(err, "clCreateKernel");

    /* ---------- Alokasi buffer device ---------- */
    double t_h2d_start = now_sec();

    cl_mem d_payloads = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                       (size_t)n * KERNEL_MAX_PAYLOAD, h_payloads, &err);
    CHECK_CL(err, "buf payloads");

    cl_mem d_patterns = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                       (size_t)P * KERNEL_MAX_PATTERN, h_patterns, &err);
    CHECK_CL(err, "buf patterns");

    cl_mem d_sev = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                  sizeof(int) * P, h_sev, &err);
    CHECK_CL(err, "buf sev");

    cl_mem d_match = clCreateBuffer(context, CL_MEM_WRITE_ONLY,
                                    (size_t)n * P, NULL, &err);
    CHECK_CL(err, "buf match");

    cl_mem d_threats = clCreateBuffer(context, CL_MEM_WRITE_ONLY,
                                      sizeof(int) * n, NULL, &err);
    CHECK_CL(err, "buf threats");

    cl_mem d_sev_log = clCreateBuffer(context, CL_MEM_WRITE_ONLY,
                                      sizeof(int) * n, NULL, &err);
    CHECK_CL(err, "buf sev_log");

    double t_h2d = now_sec() - t_h2d_start;

    /* ---------- Set args & launch ---------- */
    clSetKernelArg(kernel, 0, sizeof(cl_mem), &d_payloads);
    clSetKernelArg(kernel, 1, sizeof(cl_mem), &d_patterns);
    clSetKernelArg(kernel, 2, sizeof(cl_mem), &d_sev);
    clSetKernelArg(kernel, 3, sizeof(int),    &n);
    clSetKernelArg(kernel, 4, sizeof(int),    &P);
    clSetKernelArg(kernel, 5, sizeof(cl_mem), &d_match);
    clSetKernelArg(kernel, 6, sizeof(cl_mem), &d_threats);
    clSetKernelArg(kernel, 7, sizeof(cl_mem), &d_sev_log);

    size_t local_size  = 64;
    size_t global_size = ((n + local_size - 1) / local_size) * local_size;

    double t_kernel_start = now_sec();
    err = clEnqueueNDRangeKernel(queue, kernel, 1, NULL,
                                 &global_size, &local_size, 0, NULL, NULL);
    CHECK_CL(err, "clEnqueueNDRangeKernel");
    clFinish(queue);
    double t_kernel = now_sec() - t_kernel_start;

    /* ---------- D2H ---------- */
    double t_d2h_start = now_sec();
    clEnqueueReadBuffer(queue, d_match,   CL_TRUE, 0, (size_t)n * P, h_match, 0, NULL, NULL);
    clEnqueueReadBuffer(queue, d_threats, CL_TRUE, 0, sizeof(int) * n, h_threats_per_log, 0, NULL, NULL);
    clEnqueueReadBuffer(queue, d_sev_log, CL_TRUE, 0, sizeof(int) * n, h_sev_per_log, 0, NULL, NULL);
    double t_d2h = now_sec() - t_d2h_start;

    /* ---------- Agregasi hasil di host ---------- */
    int  total_threats = 0;
    int  sev_hist[5]   = {0};
    int  pat_hits[NUM_PATTERNS] = {0};

    for (int i = 0; i < n; i++) total_threats += h_threats_per_log[i];

    for (int i = 0; i < n; i++)
        for (int p = 0; p < P; p++)
            if (h_match[i * P + p]) {
                pat_hits[p]++;
                sev_hist[ATTACK_PATTERNS[p].severity]++;
            }

    printf("--- Hasil Analisis ---\n");
    printf("Total threat terdeteksi : %d\n", total_threats);
    printf("Critical (Lv.4)         : %d\n", sev_hist[4]);
    printf("High     (Lv.3)         : %d\n", sev_hist[3]);
    printf("Medium   (Lv.2)         : %d\n", sev_hist[2]);
    printf("Low      (Lv.1)         : %d\n\n", sev_hist[1]);

    printf("--- Pattern Hit ---\n");
    for (int p = 0; p < P; p++)
        if (pat_hits[p] > 0)
            printf("  [Sev %d] %-25s : %d hit\n",
                   ATTACK_PATTERNS[p].severity, ATTACK_PATTERNS[p].name, pat_hits[p]);

    printf("\n--- Performa OpenCL ---\n");
    printf("Host → Device   : %.4f detik\n", t_h2d);
    printf("Eksekusi kernel : %.4f detik\n", t_kernel);
    printf("Device → Host   : %.4f detik\n", t_d2h);
    printf("Total GPU time  : %.4f detik\n", t_h2d + t_kernel + t_d2h);
    printf("Throughput      : %.0f log/detik (kernel only)\n", n / t_kernel);

    /* ---------- Cleanup ---------- */
    clReleaseMemObject(d_payloads);
    clReleaseMemObject(d_patterns);
    clReleaseMemObject(d_sev);
    clReleaseMemObject(d_match);
    clReleaseMemObject(d_threats);
    clReleaseMemObject(d_sev_log);
    clReleaseKernel(kernel);
    clReleaseProgram(program);
    clReleaseCommandQueue(queue);
    clReleaseContext(context);
    free(platforms); free(src);
    free(h_payloads); free(h_patterns); free(h_sev);
    free(h_match); free(h_threats_per_log); free(h_sev_per_log);
    free(logs);
    return 0;
}
