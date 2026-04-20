/*
 * 密文磁盘格式：魔数 CTB5 + 版本号(6) + LSSS(M,rho) + 群元素(R,C,Cp,Crows) + AES 载荷 +
 * AM 头(k_attr, hdr_node, E_hdr)。G1/GT 经 abe_io 顶层 element_to_bytes（u32 实际长度 w）往返。
 * CLI：cmd_encrypt 末尾 abe_ct_save；cmd_decrypt 开头 abe_ct_load。
 */
#include "abe_ct_pack.h"
#include "abe_io.h"
#include <stdlib.h>
#include <string.h>

int abe_ct_save(pairing_t pairing, const abe_ct_t *ct, FILE *f) {
  (void)pairing;
  uint32_t magic = ABE_CT_FILE_MAGIC;
  if (abe_io_write_u32(f, magic) != 0 || abe_io_write_u32(f, 6) != 0) return -1;
  if (abe_io_write_u32(f, (uint32_t)ct->l) != 0 || abe_io_write_u32(f, (uint32_t)ct->n) != 0) return -1;
  int ln = ct->l * ct->n;
  for (int i = 0; i < ln; i++) {
    if (abe_io_write_u32(f, (uint32_t)ct->M[i]) != 0) return -1;
  }
  for (int i = 0; i < ct->l; i++) {
    if (abe_io_write_u32(f, (uint32_t)ct->rho[i]) != 0) return -1;
  }
  if (abe_io_write_gt(f, ct->R) != 0 || abe_io_write_gt(f, ct->C) != 0 || abe_io_write_g1(f, ct->Cp) != 0) return -1;
  for (int i = 0; i < ct->l; i++) {
    if (abe_io_write_g1(f, ct->Crows[i]) != 0) return -1;
  }
  if (abe_io_write_u64(f, (uint64_t)ct->ct_sym_len) != 0) return -1;
  if (ct->ct_sym_len > 0 && abe_io_write_bytes(f, ct->ct_sym, ct->ct_sym_len) != 0) return -1;

  if (abe_io_write_u32(f, (uint32_t)ct->n_hdr) != 0) return -1;
  for (int i = 0; i < ct->n_hdr; i++) {
    if (abe_io_write_zr(f, ct->k_attr[i]) != 0) return -1;
  }
  for (int i = 0; i < ct->n_hdr; i++) {
    if (abe_io_write_u32(f, (uint32_t)ct->hdr_node[i]) != 0) return -1;
  }
  for (int i = 0; i < ct->n_hdr; i++) {
    uint8_t has = (ct->E_hdr[i] != NULL) ? 1 : 0;
    if (abe_io_write_bytes(f, &has, 1) != 0) return -1;
    if (has && abe_io_write_g1(f, *ct->E_hdr[i]) != 0) return -1;
  }
  return 0;
}

int abe_ct_load(pairing_t pairing, abe_ct_t *ct, FILE *f) {
  memset(ct, 0, sizeof(*ct));
  uint32_t magic = 0, ver = 0;
  if (abe_io_read_u32(f, &magic) != 0 || magic != ABE_CT_FILE_MAGIC) return -1;
  if (abe_io_read_u32(f, &ver) != 0 || ver != 6) return -1;
  uint32_t l = 0, n = 0;
  if (abe_io_read_u32(f, &l) != 0 || abe_io_read_u32(f, &n) != 0) return -1;
  ct->l = (int)l;
  ct->n = (int)n;
  if (ct->l <= 0 || ct->n <= 0) return -1;
  int ln = ct->l * ct->n;
  ct->M = (int *)malloc(sizeof(int) * (size_t)ln);
  ct->rho = (int *)malloc(sizeof(int) * (size_t)ct->l);
  if (!ct->M || !ct->rho) return -1;
  /* 先初始化 R/C/Cp 再读矩阵，避免读失败 goto fail 时 abe_ct_clear(l>0) 清到未 init 的群元 */
  element_init_GT(ct->R, pairing);
  element_init_GT(ct->C, pairing);
  element_init_G1(ct->Cp, pairing);
  for (int i = 0; i < ln; i++) {
    uint32_t v = 0;
    if (abe_io_read_u32(f, &v) != 0) goto fail;
    ct->M[i] = (int)v;
  }
  for (int i = 0; i < ct->l; i++) {
    uint32_t v = 0;
    if (abe_io_read_u32(f, &v) != 0) goto fail;
    ct->rho[i] = (int)v;
  }
  if (abe_io_read_gt(f, ct->R) != 0 || abe_io_read_gt(f, ct->C) != 0 || abe_io_read_g1(pairing, f, ct->Cp) != 0) goto fail;
  ct->Crows = (element_t *)malloc(sizeof(element_t) * (size_t)ct->l);
  if (!ct->Crows) goto fail;
  for (int i = 0; i < ct->l; i++) element_init_G1(ct->Crows[i], pairing);
  for (int i = 0; i < ct->l; i++) {
    if (abe_io_read_g1(pairing, f, ct->Crows[i]) != 0) goto fail;
  }
  uint64_t slen = 0;
  if (abe_io_read_u64(f, &slen) != 0) goto fail;
  ct->ct_sym_len = (size_t)slen;
  ct->ct_sym = (uint8_t *)malloc(ct->ct_sym_len ? ct->ct_sym_len : 1);
  if (!ct->ct_sym) goto fail;
  if (ct->ct_sym_len > 0 && abe_io_read_bytes(f, ct->ct_sym, ct->ct_sym_len) != 0) goto fail;

  uint32_t nh = 0;
  if (abe_io_read_u32(f, &nh) != 0) goto fail;
  ct->n_hdr = (int)nh;
  ct->k_attr = (element_t *)malloc(sizeof(element_t) * (size_t)ct->n_hdr);
  ct->hdr_node = (int *)malloc(sizeof(int) * (size_t)ct->n_hdr);
  ct->E_hdr = (element_t **)calloc((size_t)ct->n_hdr, sizeof(element_t *));
  if (!ct->k_attr || !ct->hdr_node || !ct->E_hdr) goto fail;
  for (int i = 0; i < ct->n_hdr; i++) element_init_Zr(ct->k_attr[i], pairing);
  for (int i = 0; i < ct->n_hdr; i++) {
    if (abe_io_read_zr(f, ct->k_attr[i]) != 0) goto fail;
  }
  for (int i = 0; i < ct->n_hdr; i++) {
    uint32_t hn = 0;
    if (abe_io_read_u32(f, &hn) != 0) goto fail;
    ct->hdr_node[i] = (int)hn;
  }
  for (int i = 0; i < ct->n_hdr; i++) {
    uint8_t has = 0;
    if (abe_io_read_bytes(f, &has, 1) != 0) goto fail;
    if (has) {
      ct->E_hdr[i] = (element_t *)malloc(sizeof(element_t));
      element_init_G1(*ct->E_hdr[i], pairing);
      if (abe_io_read_g1(pairing, f, *ct->E_hdr[i]) != 0) goto fail;
    } else
      ct->E_hdr[i] = NULL;
  }
  return 0;
fail:
  abe_ct_clear(pairing, ct);
  return -1;
}
