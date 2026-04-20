#include "abe_io.h"
#include <gmp.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ABE_ELEM_RAW_MAX 2048
#define ABE_ELEM_WIRE_MAX (262144)

int abe_io_write_u32(FILE *f, uint32_t v) {
  unsigned char b[4];
  b[0] = (unsigned char)(v & 0xff);
  b[1] = (unsigned char)((v >> 8) & 0xff);
  b[2] = (unsigned char)((v >> 16) & 0xff);
  b[3] = (unsigned char)((v >> 24) & 0xff);
  return fwrite(b, 1, 4, f) == 4 ? 0 : -1;
}

int abe_io_read_u32(FILE *f, uint32_t *v) {
  unsigned char b[4];
  if (fread(b, 1, 4, f) != 4) return -1;
  *v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
  return 0;
}

int abe_io_write_u64(FILE *f, uint64_t v) {
  if (abe_io_write_u32(f, (uint32_t)(v & 0xffffffffu)) != 0) return -1;
  return abe_io_write_u32(f, (uint32_t)(v >> 32));
}

int abe_io_read_u64(FILE *f, uint64_t *v) {
  uint32_t lo, hi;
  if (abe_io_read_u32(f, &lo) != 0 || abe_io_read_u32(f, &hi) != 0) return -1;
  *v = (uint64_t)lo | ((uint64_t)hi << 32);
  return 0;
}

int abe_io_write_bytes(FILE *f, const void *p, size_t n) { return fwrite(p, 1, n, f) == n ? 0 : -1; }

int abe_io_read_bytes(FILE *f, void *p, size_t n) { return fread(p, 1, n, f) == n ? 0 : -1; }

static void mpz_out_raw_n(unsigned char *data, int n, mpz_t z) {
  size_t count;
  if (mpz_sgn(z)) {
    count = (mpz_sizeinbase(z, 2) + 7) / 8;
    mpz_export(&data[n - count], NULL, 1, 1, 1, 0, z);
    memset(data, 0, n - count);
  } else {
    memset(data, 0, (size_t)n);
  }
}

static int fp_leaf_write_ep(FILE *f, element_ptr e) {
  int n = element_length_in_bytes(e);
  if (n <= 0 || n > ABE_ELEM_RAW_MAX) return -1;
  mpz_t z;
  mpz_init(z);
  element_to_mpz(z, e);
  if (mpz_sgn(z) < 0 && e->field && mpz_sgn(e->field->order) > 0) {
    mpz_add(z, z, e->field->order);
  }
  if (abe_io_write_u32(f, (uint32_t)n) != 0) {
    mpz_clear(z);
    return -1;
  }
  unsigned char *buf = (unsigned char *)calloc((size_t)n, 1);
  if (!buf) {
    mpz_clear(z);
    return -1;
  }
  size_t count = mpz_sgn(z) ? (size_t)((mpz_sizeinbase(z, 2) + 7) / 8) : 0;
  if (count > (size_t)n) {
    free(buf);
    mpz_clear(z);
    return -1;
  }
  mpz_out_raw_n(buf, n, z);
  mpz_clear(z);
  int r = abe_io_write_bytes(f, buf, (size_t)n);
  free(buf);
  return r;
}

static int fp_leaf_read(FILE *f, element_t e) {
  uint32_t n32 = 0;
  if (abe_io_read_u32(f, &n32) != 0) return -1;
  int n = (int)n32;
  if (n <= 0 || n > ABE_ELEM_RAW_MAX) return -1;
  unsigned char *buf = (unsigned char *)malloc((size_t)n);
  if (!buf) return -1;
  if (abe_io_read_bytes(f, buf, (size_t)n) != 0) {
    free(buf);
    return -1;
  }
  mpz_t z;
  mpz_init(z);
  mpz_import(z, n, 1, 1, 1, 0, buf);
  element_set_mpz(e, z);
  mpz_clear(z);
  free(buf);
  return 0;
}

static int write_composite_ep(FILE *f, element_ptr e) {
  int ic = element_item_count(e);
  if (ic == 0) return fp_leaf_write_ep(f, e);
  for (int i = 0; i < ic; i++) {
    element_ptr ch = element_item(e, i);
    if (!ch) return -1;
    if (write_composite_ep(f, ch) != 0) return -1;
  }
  return 0;
}

static int read_composite(FILE *f, element_t e) {
  int ic = element_item_count(e);
  if (ic == 0) return fp_leaf_read(f, e);
  for (int i = 0; i < ic; i++) {
    element_ptr ch = element_item(e, i);
    if (!ch) return -1;
    if (read_composite(f, ch) != 0) return -1;
  }
  return 0;
}

/* G1/GT：顶层 element_to/from_bytes，磁盘存实际写出长度 w（不定长压缩编码常见）。读前 element_set0。 */
static int abe_io_wire_write(FILE *f, element_ptr e) {
  int n = element_length_in_bytes(e);
  if (n <= 0 || n > ABE_ELEM_WIRE_MAX) return -1;
  unsigned char *buf = (unsigned char *)calloc((size_t)n, 1);
  if (!buf) return -1;
  int w = element_to_bytes(buf, e);
  if (w <= 0 || w > n) {
    free(buf);
    return -1;
  }
  if (abe_io_write_u32(f, (uint32_t)w) != 0) {
    free(buf);
    return -1;
  }
  int r = abe_io_write_bytes(f, buf, (size_t)w);
  free(buf);
  return r;
}

static int abe_io_wire_read(FILE *f, element_t e) {
  uint32_t w32 = 0;
  if (abe_io_read_u32(f, &w32) != 0) return -1;
  int w = (int)w32;
  if (w <= 0 || w > ABE_ELEM_WIRE_MAX) return -1;
  unsigned char *buf = (unsigned char *)malloc((size_t)w);
  if (!buf) return -1;
  if (abe_io_read_bytes(f, buf, (size_t)w) != 0) {
    free(buf);
    return -1;
  }
  element_set0(e);
  int rr = element_from_bytes(e, buf);
  free(buf);
  return rr > 0 ? 0 : -1;
}

int abe_io_write_zr(FILE *f, const element_t e) { return fp_leaf_write_ep(f, (element_ptr)e); }

int abe_io_read_zr(FILE *f, element_t e) { return fp_leaf_read(f, e); }

int abe_io_write_g1(FILE *f, const element_t g) { return abe_io_wire_write(f, (element_ptr)g); }

int abe_io_read_g1(pairing_t pairing, FILE *f, element_t g) {
  (void)pairing;
  return abe_io_wire_read(f, g);
}

int abe_io_write_gt(FILE *f, const element_t gt) { return abe_io_wire_write(f, (element_ptr)gt); }

int abe_io_read_gt(FILE *f, element_t gt) { return abe_io_wire_read(f, gt); }