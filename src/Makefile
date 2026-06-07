# ============================================================
# Makefile - Parallel IDS Log Analyzer
# ============================================================
CC      = gcc
CFLAGS  = -O2 -Wall -Wno-unused-result
OMPFLAG = -fopenmp
CLLIB   = -lOpenCL

# Detect OpenCL pada macOS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    CLLIB = -framework OpenCL
endif

all: log_generator ids_sequential ids_openmp ids_opencl ids_hybrid

log_generator: log_generator.c ids_common.h
	$(CC) $(CFLAGS) log_generator.c -o $@

ids_sequential: ids_sequential.c log_loader.c ids_common.h
	$(CC) $(CFLAGS) ids_sequential.c log_loader.c -o $@

ids_openmp: ids_openmp.c log_loader.c ids_common.h
	$(CC) $(CFLAGS) $(OMPFLAG) ids_openmp.c log_loader.c -o $@

ids_opencl: ids_opencl.c log_loader.c ids_common.h
	$(CC) $(CFLAGS) ids_opencl.c log_loader.c -o $@ $(CLLIB)

ids_hybrid: ids_hybrid.c log_loader.c ids_common.h
	$(CC) $(CFLAGS) $(OMPFLAG) ids_hybrid.c log_loader.c -o $@ $(CLLIB)

# Bangun dataset uji
generate: log_generator
	./log_generator 100000 network_logs.txt

# Jalankan benchmark perbandingan
benchmark: all generate
	@echo "===== Benchmark Sequential ====="
	@./ids_sequential network_logs.txt | tail -5
	@echo ""
	@echo "===== Benchmark OpenMP (semua thread) ====="
	@./ids_openmp network_logs.txt | tail -5
	@echo ""
	@echo "===== Benchmark OpenCL (GPU) ====="
	@./ids_opencl network_logs.txt | tail -6
	@echo ""
	@echo "===== Benchmark Hybrid ====="
	@./ids_hybrid network_logs.txt | tail -6

clean:
	rm -f log_generator ids_sequential ids_openmp ids_opencl ids_hybrid network_logs.txt

.PHONY: all generate benchmark clean
