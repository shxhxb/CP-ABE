/*
 * 状态目录持久化：pairing 参数字符串、pk/msk、apk+ask、KEK 树、用户 sk/tk/ku。
 * 供 load_state / cmd_init / cmd_keygen 使用；与 abe_core 中结构体布局一一对应。
 */
#include "abe_state.h"
#include "abe_io.h"
#include <stdlib.h>
#include <string.h>

int abe_state_save_param(const char *path, pbc_param_t param) {
  FILE *f = fopen(path, "wb");
  if (!f) return -1;
  pbc_param_out_str(f, param);
  fclose(f);
  return 0;
}

int abe_state_load_param(const char *path, pbc_param_t param) {
  FILE *f = fopen(path, "rb");
  if (!f) return -1;
  fseek(f, 0, SEEK_END);
  long sz = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (sz < 0 || sz > 1 << 22) {
    fclose(f);
    return -1;
  }
  char *buf = (char *)malloc((size_t)sz + 1);
  if (!buf) {
    fclose(f);
    return -1;
  }
  if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
    free(buf);
    fclose(f);
    return -1;
  }
  fclose(f);
  buf[sz] = '\0';
  /* Windows 文本换行可能含 \r，避免 init_set_str 解析失败或得到不一致配对 */
  char *w = buf;
  char *r = buf;
  while (*r) {
    if (*r != '\r') *w++ = *r;
    r++;
  }
  *w = '\0';
  int e = pbc_param_init_set_str(param, buf);
  free(buf);
  return e;
}

int abe_state_save_pk(FILE *f, const abe_pk_t *pk) {
  if (abe_io_write_u32(f, ABE_STATE_MAGIC_PK) != 0) return -1;
  if (abe_io_write_bytes(f, pk->k1, 32) != 0 || abe_io_write_bytes(f, pk->k2, 32) != 0) return -1;
  if (abe_io_write_g1(f, pk->g) != 0 || abe_io_write_g1(f, pk->g_alpha) != 0) return -1;
  return abe_io_write_gt(f, pk->e_gg);
}

int abe_state_load_pk(pairing_t pairing, abe_pk_t *pk, FILE *f) {
  uint32_t magic = 0;
  if (abe_io_read_u32(f, &magic) != 0 || magic != ABE_STATE_MAGIC_PK) return -1;
  if (abe_io_read_bytes(f, pk->k1, 32) != 0 || abe_io_read_bytes(f, pk->k2, 32) != 0) return -1;
  element_init_G1(pk->g, pairing);
  element_init_G1(pk->g_alpha, pairing);
  element_init_GT(pk->e_gg, pairing);
  if (abe_io_read_g1(pairing, f, pk->g) != 0 || abe_io_read_g1(pairing, f, pk->g_alpha) != 0 || abe_io_read_gt(f, pk->e_gg) != 0)
    return -1;
  return 0;
}

int abe_state_save_msk(FILE *f, const abe_msk_t *msk) {
  if (abe_io_write_u32(f, ABE_STATE_MAGIC_MS) != 0) return -1;
  if (abe_io_write_bytes(f, msk->k1, 32) != 0 || abe_io_write_bytes(f, msk->k2, 32) != 0) return -1;
  return abe_io_write_zr(f, msk->alpha);
}

int abe_state_load_msk(pairing_t pairing, abe_msk_t *msk, FILE *f) {
  uint32_t magic = 0;
  if (abe_io_read_u32(f, &magic) != 0 || magic != ABE_STATE_MAGIC_MS) return -1;
  if (abe_io_read_bytes(f, msk->k1, 32) != 0 || abe_io_read_bytes(f, msk->k2, 32) != 0) return -1;
  element_init_Zr(msk->alpha, pairing);
  return abe_io_read_zr(f, msk->alpha);
}

int abe_state_save_apk_ask(FILE *fapk, FILE *fask, const abe_apk_t *apk, const abe_ask_t *ask) {
  if (abe_io_write_u32(fapk, ABE_STATE_MAGIC_AP) != 0 || abe_io_write_u32(fask, ABE_STATE_MAGIC_AS) != 0) return -1;
  if (abe_io_write_u32(fapk, (uint32_t)apk->n_attrs) != 0 || abe_io_write_u32(fask, (uint32_t)ask->n_attrs) != 0)
    return -1;
  if (apk->n_attrs != ask->n_attrs) return -1;
  for (int i = 0; i < apk->n_attrs; i++) {
    if (abe_io_write_g1(fapk, apk->t[i]) != 0) return -1;
    if (abe_io_write_zr(fask, ask->t[i]) != 0) return -1;
  }
  return 0;
}

int abe_state_load_apk_ask(pairing_t pairing, abe_apk_t *apk, abe_ask_t *ask, FILE *fapk, FILE *fask) {
  uint32_t ma = 0, ms = 0;
  if (abe_io_read_u32(fapk, &ma) != 0 || ma != ABE_STATE_MAGIC_AP) return -1;
  if (abe_io_read_u32(fask, &ms) != 0 || ms != ABE_STATE_MAGIC_AS) return -1;
  uint32_t na = 0, ns = 0;
  if (abe_io_read_u32(fapk, &na) != 0 || abe_io_read_u32(fask, &ns) != 0) return -1;
  if (na != ns) return -1;
  apk->n_attrs = (int)na;
  ask->n_attrs = (int)ns;
  apk->t = (element_t *)malloc(sizeof(element_t) * (size_t)apk->n_attrs);
  ask->t = (element_t *)malloc(sizeof(element_t) * (size_t)ask->n_attrs);
  if (!apk->t || !ask->t) return -1;
  for (int i = 0; i < apk->n_attrs; i++) {
    element_init_G1(apk->t[i], pairing);
    element_init_Zr(ask->t[i], pairing);
    if (abe_io_read_g1(pairing, fapk, apk->t[i]) != 0 || abe_io_read_zr(fask, ask->t[i]) != 0) return -1;
  }
  return 0;
}

int abe_state_save_tree(FILE *f, const kek_tree_t *t) {
  if (abe_io_write_u32(f, ABE_STATE_MAGIC_KT) != 0) return -1;
  if (abe_io_write_u32(f, (uint32_t)t->n_nodes) != 0 || abe_io_write_u32(f, (uint32_t)t->n_users) != 0) return -1;
  if (abe_io_write_u32(f, (uint32_t)t->root) != 0) return -1;
  for (int i = 0; i < t->n_nodes; i++) {
    kt_node_t *nd = &t->nodes[i];
    if (abe_io_write_u32(f, (uint32_t)nd->id) != 0 || abe_io_write_u32(f, (uint32_t)nd->left) != 0 ||
        abe_io_write_u32(f, (uint32_t)nd->right) != 0 || abe_io_write_u32(f, (uint32_t)nd->parent) != 0 ||
        abe_io_write_u32(f, (uint32_t)nd->leaf_user) != 0)
      return -1;
  }
  for (int i = 0; i < t->n_users; i++) {
    if (abe_io_write_u32(f, (uint32_t)t->leaf_of_user[i]) != 0) return -1;
  }
  for (int i = 0; i < t->n_nodes; i++) {
    if (abe_io_write_zr(f, t->theta[i]) != 0) return -1;
  }
  return 0;
}

int abe_state_load_tree(pairing_t pairing, kek_tree_t *t, FILE *f) {
  memset(t, 0, sizeof(*t));
  uint32_t magic = 0;
  if (abe_io_read_u32(f, &magic) != 0 || magic != ABE_STATE_MAGIC_KT) return -1;
  uint32_t nn = 0, nu = 0, root = 0;
  if (abe_io_read_u32(f, &nn) != 0 || abe_io_read_u32(f, &nu) != 0 || abe_io_read_u32(f, &root) != 0) return -1;
  t->n_nodes = (int)nn;
  t->n_users = (int)nu;
  t->root = (int)root;
  t->nodes = (kt_node_t *)calloc((size_t)t->n_nodes, sizeof(kt_node_t));
  t->leaf_of_user = (int *)malloc(sizeof(int) * (size_t)t->n_users);
  t->theta = (element_t *)malloc(sizeof(element_t) * (size_t)t->n_nodes);
  if (!t->nodes || !t->leaf_of_user || !t->theta) return -1;
  for (int i = 0; i < t->n_nodes; i++) {
    uint32_t a, b, c, d, e;
    if (abe_io_read_u32(f, &a) != 0 || abe_io_read_u32(f, &b) != 0 || abe_io_read_u32(f, &c) != 0 ||
        abe_io_read_u32(f, &d) != 0 || abe_io_read_u32(f, &e) != 0)
      return -1;
    t->nodes[i].id = (int)a;
    t->nodes[i].left = (int)b;
    t->nodes[i].right = (int)c;
    t->nodes[i].parent = (int)d;
    t->nodes[i].leaf_user = (int)e;
  }
  for (int i = 0; i < t->n_users; i++) {
    uint32_t l = 0;
    if (abe_io_read_u32(f, &l) != 0) return -1;
    t->leaf_of_user[i] = (int)l;
  }
  for (int i = 0; i < t->n_nodes; i++) {
    element_init_Zr(t->theta[i], pairing);
    if (abe_io_read_zr(f, t->theta[i]) != 0) return -1;
  }
  return 0;
}

int abe_state_save_sk(FILE *f, const abe_sk_t *sk) {
  if (abe_io_write_u32(f, ABE_STATE_MAGIC_SK) != 0) return -1;
  if (abe_io_write_g1(f, sk->K) != 0 || abe_io_write_g1(f, sk->L) != 0) return -1;
  if (abe_io_write_zr(f, sk->z) != 0) return -1;
  if (abe_io_write_u64(f, (uint64_t)sk->trace_len) != 0) return -1;
  if (sk->trace_len > 0 && abe_io_write_bytes(f, sk->trace_ct, sk->trace_len) != 0) return -1;
  return 0;
}

int abe_state_load_sk(pairing_t pairing, abe_sk_t *sk, FILE *f) {
  memset(sk, 0, sizeof(*sk));
  uint32_t magic = 0;
  if (abe_io_read_u32(f, &magic) != 0 || magic != ABE_STATE_MAGIC_SK) return -1;
  element_init_G1(sk->K, pairing);
  element_init_G1(sk->L, pairing);
  element_init_Zr(sk->z, pairing);
  if (abe_io_read_g1(pairing, f, sk->K) != 0 || abe_io_read_g1(pairing, f, sk->L) != 0 || abe_io_read_zr(f, sk->z) != 0) return -1;
  uint64_t tl = 0;
  if (abe_io_read_u64(f, &tl) != 0) return -1;
  sk->trace_len = (size_t)tl;
  if (sk->trace_len > (size_t)1 << 30) return -1;
  sk->trace_ct = (uint8_t *)malloc(sk->trace_len ? sk->trace_len : 1);
  if (!sk->trace_ct) return -1;
  if (sk->trace_len > 0 && abe_io_read_bytes(f, sk->trace_ct, sk->trace_len) != 0) return -1;
  return 0;
}

int abe_state_save_tk(FILE *f, const abe_tk_t *tk, int n_attrs) {
  if (abe_io_write_u32(f, ABE_STATE_MAGIC_TK) != 0) return -1;
  if (abe_io_write_u32(f, (uint32_t)n_attrs) != 0) return -1;
  if (abe_io_write_g1(f, tk->K1) != 0) return -1;
  for (int i = 0; i < n_attrs; i++) {
    if (abe_io_write_g1(f, tk->K_attr[i]) != 0) return -1;
  }
  return 0;
}

int abe_state_load_tk(pairing_t pairing, abe_tk_t *tk, int n_attrs, FILE *f) {
  memset(tk, 0, sizeof(*tk));
  uint32_t magic = 0, na = 0;
  if (abe_io_read_u32(f, &magic) != 0 || magic != ABE_STATE_MAGIC_TK) return -1;
  if (abe_io_read_u32(f, &na) != 0 || (int)na != n_attrs) return -1;
  element_init_G1(tk->K1, pairing);
  tk->K_attr = (element_t *)malloc(sizeof(element_t) * (size_t)n_attrs);
  if (!tk->K_attr) return -1;
  if (abe_io_read_g1(pairing, f, tk->K1) != 0) return -1;
  for (int i = 0; i < n_attrs; i++) {
    element_init_G1(tk->K_attr[i], pairing);
    if (abe_io_read_g1(pairing, f, tk->K_attr[i]) != 0) return -1;
  }
  return 0;
}

int abe_state_save_ku(FILE *f, const abe_kek_user_t *ku, int n_attrs) {
  if (abe_io_write_u32(f, ABE_KU_MAGIC) != 0) return -1;
  if (abe_io_write_u32(f, (uint32_t)n_attrs) != 0) return -1;
  for (int i = 0; i < n_attrs; i++) {
    if (abe_io_write_g1(f, ku->kek[i]) != 0) return -1;
  }
  for (int i = 0; i < n_attrs; i++) {
    if (abe_io_write_u32(f, (uint32_t)ku->phi_node[i]) != 0) return -1;
  }
  return 0;
}

int abe_state_load_ku(pairing_t pairing, abe_kek_user_t *ku, int n_attrs, FILE *f) {
  memset(ku, 0, sizeof(*ku));
  uint32_t magic = 0, na = 0;
  if (abe_io_read_u32(f, &magic) != 0 || magic != ABE_KU_MAGIC) return -1;
  if (abe_io_read_u32(f, &na) != 0 || (int)na != n_attrs) return -1;
  ku->kek = (element_t *)malloc(sizeof(element_t) * (size_t)n_attrs);
  ku->phi_node = (int *)malloc(sizeof(int) * (size_t)n_attrs);
  if (!ku->kek || !ku->phi_node) return -1;
  for (int i = 0; i < n_attrs; i++) {
    element_init_G1(ku->kek[i], pairing);
    if (abe_io_read_g1(pairing, f, ku->kek[i]) != 0) return -1;
  }
  for (int i = 0; i < n_attrs; i++) {
    uint32_t p = 0;
    if (abe_io_read_u32(f, &p) != 0) return -1;
    ku->phi_node[i] = (int)p;
  }
  (void)pairing;
  return 0;
}
