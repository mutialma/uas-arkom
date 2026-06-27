# Parallel Intrusion Detection System (IDS) Log Analyzer

Sistem analisis log jaringan secara **paralel** untuk mendeteksi pola serangan siber menggunakan **OpenMP** (multi-core CPU) dan **OpenCL** (GPU/heterogeneous).
#Mutia Alma Sovia			 25032014058 
#Yoga Candra Putra			 25032014053 
#Muhammad Ibnu Reza   	 25032014031 

## Arsitektur

```
┌─────────────────┐     ┌────────────────────┐     ┌────────────────────┐
│  Log Generator  │ →  │  Log Loader (I/O)  │ →  │   Engine Analisis  │
│  (sintetis)     │     │  parse → struct    │     │  Sequential        │
└─────────────────┘     └────────────────────┘     │  OpenMP            │
                                                    │  OpenCL            │
                                                    │  Hybrid (OMP+OCL)  │
                                                    └────────────────────┘
                                                              ↓
                                                    ┌────────────────────┐
                                                    │   Laporan Threat   │
                                                    │ - Histogram severity│
                                                    │ - Top attacker IP   │
                                                    │ - Pattern hit count │
                                                    │ - Benchmark waktu   │
                                                    └────────────────────┘
```

## Komponen

| File | Peran |
|---|---|
| `ids_common.h` | Struktur data (`LogEntry`, `Threat`, `AttackPattern`) + 15 pola serangan |
| `log_generator.c` | Membuat log sintetis (~15% mengandung serangan) |
| `log_loader.c` | Parser file log → array `LogEntry` |
| `ids_sequential.c` | Baseline 1-thread (Boyer-Moore Horspool) |
| `ids_openmp.c` | Paralelisasi loop log dengan `#pragma omp parallel for` + reduction |
| `ids_kernel.cl` | Kernel GPU: 1 work-item = 1 log, cocokkan ke seluruh pattern |
| `ids_opencl.c` | Host OpenCL: setup context, transfer H↔D, launch kernel |
| `ids_hybrid.c` | Pipeline OpenMP (preprocess + agregasi) + OpenCL (matching) |
| `Makefile` | Build target & benchmark |

## Pola Serangan yang Dideteksi

15 signature mencakup: **SQL Injection** (klasik & UNION), **XSS**, **Path Traversal**, **Command Injection**, **Brute Force SSH**, **Port Scan**, **DDoS Flood**, **Malware C2**, **Backdoor (web shell)**, **LFI/RFI**, dan **Buffer Overflow**, masing-masing dengan level severity 1–4.

## Strategi Paralelisasi

**OpenMP** — paralelisasi *data-parallel* pada loop log:
```c
#pragma omp parallel
{
    int local_hist[5] = {0};        // buffer per-thread → hindari false sharing
    #pragma omp for schedule(dynamic, 256) reduction(+:threat_count)
    for (int i = 0; i < n; i++) { /* match patterns */ }
    #pragma omp critical { /* merge ke global */ }
}
```
- `schedule(dynamic, 256)` → load balancing saat panjang payload bervariasi
- `reduction` untuk counter, buffer thread-local untuk histogram → minim contention
- `critical` hanya saat menulis daftar threat detail

**OpenCL** — *massive parallelism* di GPU:
- Payload diratakan ke array stride-tetap (256 byte/log) untuk *coalesced memory access*
- 1 work-item memproses 1 log, melawan semua pattern
- Pattern + severity disimpan di `__constant` memory (cached, broadcast cepat)
- Work-group size 64 → kelipatan warp/wavefront yang lazim
- Output matrix biner `[n × P]` → host melakukan agregasi

**Hybrid** — pipeline 3 tahap:
1. **Preprocess** (OpenMP) — normalisasi & flatten payload, paralel di CPU
2. **Pattern matching** (OpenCL) — beban berat di GPU
3. **Agregasi** (OpenMP) — histogram, Top-5 attacker IP via hash table dengan `#pragma omp atomic`/`critical`

## Cara Memakai

```bash
# 1. Bangun semuanya
make all

# 2. Buat dataset uji (100.000 log)
make generate

# 3. Jalankan satu per satu
./ids_sequential network_logs.txt
./ids_openmp     network_logs.txt 8         # 8 thread
./ids_opencl     network_logs.txt
./ids_hybrid     network_logs.txt ids_kernel.cl 8

# 4. Benchmark perbandingan
make benchmark
```

## Contoh Output

```
=== IDS OpenMP Analyzer ===
Jumlah thread : 4 (max = 8)
Berhasil memuat 50000 log

--- Hasil Analisis ---
Total threat terdeteksi : 8898
Critical (Lv.4)         : 4408
High     (Lv.3)         : 3213
Medium   (Lv.2)         : 1277

--- Performa OpenMP ---
Thread aktif    : 4
Waktu analisis  : 0.0257 detik
Throughput      : 1943585 log/detik
```

## Persyaratan

- **GCC** dengan dukungan OpenMP (`-fopenmp`)
- **OpenCL** runtime + ICD loader:
  - Linux: `sudo apt install ocl-icd-opencl-dev opencl-headers` plus salah satu vendor: `nvidia-opencl`, `intel-opencl-icd`, `pocl-opencl-icd` (CPU fallback), atau `mesa-opencl-icd` (AMD)
  - macOS: framework OpenCL sudah bawaan
- Pada sistem tanpa GPU, install **POCL** untuk OpenCL CPU fallback:
  ```bash
  sudo apt install pocl-opencl-icd
  ```

## Link video

https://youtu.be/oid58q2jbCk
