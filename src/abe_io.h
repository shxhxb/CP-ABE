#ifndef ABE_IO_H
#define ABE_IO_H

/* abe_state / abe_ct_pack 底层字节流；G1/GT 顶层 element_to_bytes（u32 实际长度 w）；Zr 用 mpz 叶 */

#include <pbc/pbc.h>
#include <stdio.h>
#include <stdint.h>

int abe_io_write_u32(FILE *f, uint32_t v);
int abe_io_read_u32(FILE *f, uint32_t *v);
int abe_io_write_u64(FILE *f, uint64_t v);
int abe_io_read_u64(FILE *f, uint64_t *v);
int abe_io_write_bytes(FILE *f, const void *p, size_t n);
int abe_io_read_bytes(FILE *f, void *p, size_t n);

/* Zr：定长 mpz 导出 + element_set_mpz */
int abe_io_write_zr(FILE *f, const element_t e);
int abe_io_read_zr(FILE *f, element_t e);

/* G1：复合域 + snprint/set_str 叶 */
int abe_io_write_g1(FILE *f, const element_t g);
int abe_io_read_g1(pairing_t pairing, FILE *f, element_t g);

/* GT：按子分量递归（与 PBC 复合域结构一致） */
int abe_io_write_gt(FILE *f, const element_t gt);
int abe_io_read_gt(FILE *f, element_t gt);

#endif
