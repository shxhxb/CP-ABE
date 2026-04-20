#ifndef ABE_CT_PACK_H
#define ABE_CT_PACK_H

#include "abe_core.h"
#include <pbc/pbc.h>
#include <stdio.h>

#define ABE_CT_FILE_MAGIC 0x35425443u /* 'CTB5' Zr=mpz 叶; G1/GT=顶层 to_bytes 实际长度 w */

int abe_ct_save(pairing_t pairing, const abe_ct_t *ct, FILE *f);
int abe_ct_load(pairing_t pairing, abe_ct_t *ct, FILE *f);

#endif
