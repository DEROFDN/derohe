/*
 * Stage 2 standalone benchmark: times libdivsufsort's divsufsort() on the
 * exact same ~64-70KB fixture files the Go benchmarks use
 * (../testdata/safixtures/*.bin), so the Go-vs-C comparison isn't
 * confounded by different input bytes on each side.
 *
 * divsufsort.c/sssort.c/trsort.c/utils.c (+ headers) are the unmodified,
 * self-contained, MIT-licensed libdivsufsort sources bundled by
 * assets/tnn-miner (Tritonn204/tnn-miner) -- this file does not copy or
 * modify them, it compiles against them directly via -I.
 *
 * Build (from this directory):
 *   gcc -O2 -DHAVE_CONFIG_H \
 *     -I../../../../tnn-miner/src/crypto/astrobwtv3 \
 *     main.c \
 *     ../../../../tnn-miner/src/crypto/astrobwtv3/divsufsort.c \
 *     ../../../../tnn-miner/src/crypto/astrobwtv3/sssort.c \
 *     ../../../../tnn-miner/src/crypto/astrobwtv3/trsort.c \
 *     ../../../../tnn-miner/src/crypto/astrobwtv3/utils.c \
 *     -o sabench
 *
 * Usage:
 *   ./sabench <fixtures-dir> [reps-per-file]
 *   ./sabench --dump-sa <fixture-file> <output-file>   (for the Stage 2b
 *     cross-check: diff this dump against the Go stdlib oracle's array for
 *     the same bytes -- a suffix array is unique, so a correct algorithm
 *     must produce identical output regardless of implementation.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <math.h>

#include "divsufsort.h"

static double now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e9 + (double)ts.tv_nsec;
}

static unsigned char *read_file(const char *path, long *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); return NULL; }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc(len);
    if (fread(buf, 1, len, f) != (size_t)len) { fclose(f); free(buf); return NULL; }
    fclose(f);
    *out_len = len;
    return buf;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a, db = *(const double *)b;
    return (da > db) - (da < db);
}

static void bench_file(const char *path, int reps) {
    long n;
    unsigned char *text = read_file(path, &n);
    if (!text) return;

    saidx_t *sa = malloc(sizeof(saidx_t) * n);
    saidx_t *bucket_A = malloc(sizeof(saidx_t) * 256);
    saidx_t *bucket_B = malloc(sizeof(saidx_t) * 256 * 256);

    double *samples = malloc(sizeof(double) * reps);
    for (int r = 0; r < reps; r++) {
        double t0 = now_ns();
        saint_t ret = divsufsort(text, sa, (saidx_t)n, bucket_A, bucket_B);
        double t1 = now_ns();
        if (ret != 0) {
            fprintf(stderr, "%s: divsufsort returned error %d\n", path, ret);
            free(text); free(sa); free(bucket_A); free(bucket_B); free(samples);
            return;
        }
        samples[r] = t1 - t0;
    }

    qsort(samples, reps, sizeof(double), cmp_double);
    double sum = 0, mean, sd = 0;
    for (int r = 0; r < reps; r++) sum += samples[r];
    mean = sum / reps;
    for (int r = 0; r < reps; r++) sd += (samples[r] - mean) * (samples[r] - mean);
    sd = sqrt(sd / reps);
    double median = samples[reps / 2];

    printf("%-40s n=%-7ld reps=%-4d median=%9.0fns mean=%9.0fns stddev=%8.0fns\n",
           path, n, reps, median, mean, sd);

    free(text); free(sa); free(bucket_A); free(bucket_B); free(samples);
}

static void dump_sa(const char *fixture_path, const char *out_path) {
    long n;
    unsigned char *text = read_file(fixture_path, &n);
    if (!text) return;

    saidx_t *sa = malloc(sizeof(saidx_t) * n);
    saidx_t *bucket_A = malloc(sizeof(saidx_t) * 256);
    saidx_t *bucket_B = malloc(sizeof(saidx_t) * 256 * 256);

    saint_t ret = divsufsort(text, sa, (saidx_t)n, bucket_A, bucket_B);
    if (ret != 0) {
        fprintf(stderr, "%s: divsufsort returned error %d\n", fixture_path, ret);
        exit(1);
    }

    /* Little-endian int32 dump, matching how the Go side will decode it --
     * see divsufsort_bench/dump_compare_test.go. */
    FILE *out = fopen(out_path, "wb");
    for (long i = 0; i < n; i++) {
        int32_t v = (int32_t)sa[i];
        unsigned char b[4] = {
            (unsigned char)(v & 0xff),
            (unsigned char)((v >> 8) & 0xff),
            (unsigned char)((v >> 16) & 0xff),
            (unsigned char)((v >> 24) & 0xff),
        };
        fwrite(b, 1, 4, out);
    }
    fclose(out);
    printf("wrote %ld int32 suffix-array entries to %s\n", n, out_path);

    free(text); free(sa); free(bucket_A); free(bucket_B);
}

int main(int argc, char **argv) {
    if (argc >= 4 && strcmp(argv[1], "--dump-sa") == 0) {
        dump_sa(argv[2], argv[3]);
        return 0;
    }

    if (argc < 2) {
        fprintf(stderr, "usage: %s <fixtures-dir> [reps-per-file]\n", argv[0]);
        fprintf(stderr, "       %s --dump-sa <fixture-file> <output-file>\n", argv[0]);
        return 1;
    }
    const char *dir_path = argv[1];
    int reps = argc >= 3 ? atoi(argv[2]) : 10;

    DIR *dir = opendir(dir_path);
    if (!dir) { perror(dir_path); return 1; }

    struct dirent *ent;
    int count = 0;
    char full[4096];
    while ((ent = readdir(dir)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len < 4 || strcmp(ent->d_name + len - 4, ".bin") != 0) continue;
        snprintf(full, sizeof(full), "%s/%s", dir_path, ent->d_name);
        bench_file(full, reps);
        count++;
    }
    closedir(dir);

    if (count == 0) {
        fprintf(stderr, "no .bin fixtures found in %s\n", dir_path);
        return 1;
    }
    return 0;
}
