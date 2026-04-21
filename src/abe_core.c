/*
 * CP-ABE 算法体：双线性配对来自 PBC；对称部分 AES-256-CBC + SHA256 派生域元素。
 * 阅读顺序建议：abe_aa_setup → abe_am_setup → abe_aa_keygen → abe_encrypt → abe_am_encrypt
 *               → lsss_recover → abe_csp_decrypt → abe_du_decrypt → abe_keycheck / abe_trace。
 * （与 cli_cp_abe.c 中 init→keygen→encrypt→decrypt→trace 调用链逐段对齐阅读即可。）
 */
#include "abe_core.h"
#include "crypto_utils.h"
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 属性索引 att → G1 上确定一点（论文中 H(att) 的实例化） */
static void h_attr(pairing_t pairing, element_t out, int att_idx) {
  char buf[64];
  snprintf(buf, sizeof(buf), "att|%d|1|1", att_idx);
  hash_to_g1(pairing, out, buf, NULL, 0);
}

/* LSSS 矩阵第 j 列（1-based）对应的 G1 基点，用于 Crows 行装配 */
static void h_zero_col(pairing_t pairing, element_t out, int col1based) {
  char buf[64];
  snprintf(buf, sizeof(buf), "0|%d|%d|1|1", col1based, col1based);
  hash_to_g1(pairing, out, buf, NULL, 0);
}

/* TK 中 K1 的固定辅助点（与 “0|1|…” 标签绑定） */
static void h01(pairing_t pairing, element_t out) {
  hash_to_g1(pairing, out, "0|1|1|1", NULL, 0);
}

int abe_aa_setup(pairing_t pairing, abe_pk_t *pk, abe_msk_t *msk) {
  memset(pk, 0, sizeof(*pk));
  memset(msk, 0, sizeof(*msk));
  element_init_G1(pk->g, pairing);
  element_init_G1(pk->g_alpha, pairing);
  element_init_GT(pk->e_gg, pairing);
  element_init_Zr(msk->alpha, pairing);
  element_random(msk->alpha);
  element_random(pk->g);
  element_pow_zn(pk->g_alpha, pk->g, msk->alpha);
  pairing_apply(pk->e_gg, pk->g, pk->g, pairing);
  if (RAND_bytes(pk->k1, 32) != 1 || RAND_bytes(pk->k2, 32) != 1) return -1;
  memcpy(msk->k1, pk->k1, 32);
  memcpy(msk->k2, pk->k2, 32);
  return 0;
}

/* MSK 仅释放群元素；k1/k2 为定长字节，无 element_clear */
void abe_aa_clear(abe_pk_t *pk, abe_msk_t *msk) {
  element_clear(pk->g);
  element_clear(pk->g_alpha);
  element_clear(pk->e_gg);
  element_clear(msk->alpha);
}

int abe_am_setup(pairing_t pairing, const abe_pk_t *pk, abe_apk_t *apk, abe_ask_t *ask, int n_attrs) {
  apk->n_attrs = n_attrs;
  ask->n_attrs = n_attrs;
  apk->t = (element_t *)malloc(sizeof(element_t) * (size_t)n_attrs);
  ask->t = (element_t *)malloc(sizeof(element_t) * (size_t)n_attrs);
  if (!apk->t || !ask->t) return -1;
  for (int i = 0; i < n_attrs; i++) {
    element_init_G1(apk->t[i], pairing);
    element_init_Zr(ask->t[i], pairing);
    element_random(ask->t[i]);
    element_pow_zn(apk->t[i], pk->g, ask->t[i]);
  }
  return 0;
}

void abe_am_clear(abe_apk_t *apk, abe_ask_t *ask) {
  for (int i = 0; i < apk->n_attrs; i++) {
    element_clear(apk->t[i]);
    element_clear(ask->t[i]);
  }
  free(apk->t);
  free(ask->t);
  apk->t = NULL;
  ask->t = NULL;
}

void abe_ct_init(abe_ct_t *ct) { memset(ct, 0, sizeof(*ct)); }

void abe_ct_clear(pairing_t pairing, abe_ct_t *ct) {
  (void)pairing;
  if (ct->l > 0) {
    element_clear(ct->R);
    element_clear(ct->C);
    element_clear(ct->Cp);
  }
  if (ct->Crows) {
    for (int i = 0; i < ct->l; i++) element_clear(ct->Crows[i]);
    free(ct->Crows);
  }
  free(ct->M);
  free(ct->rho);
  free(ct->ct_sym);
  if (ct->k_attr && ct->n_hdr > 0) {
    for (int i = 0; i < ct->n_hdr; i++) element_clear(ct->k_attr[i]);
    free(ct->k_attr);
    ct->k_attr = NULL;
  }
  if (ct->E_hdr) {
    for (int i = 0; i < ct->n_hdr; i++) {
      if (ct->E_hdr[i]) element_clear(*ct->E_hdr[i]);
      free(ct->E_hdr[i]);
    }
    free(ct->E_hdr);
  }
  free(ct->hdr_node);
}

void abe_sk_clear(pairing_t pairing, abe_sk_t *sk) {
  (void)pairing;
  element_clear(sk->K);
  element_clear(sk->L);
  element_clear(sk->z);
  free(sk->trace_ct);
  sk->trace_ct = NULL;
}

void abe_tk_clear(pairing_t pairing, abe_tk_t *tk, int n_attrs) {
  element_clear(tk->K1);
  for (int i = 0; i < n_attrs; i++) element_clear(tk->K_attr[i]);
  free(tk->K_attr);
  tk->K_attr = NULL;
}

void abe_kek_clear(pairing_t pairing, abe_kek_user_t *ku, int n_attrs) {
  for (int i = 0; i < n_attrs; i++) element_clear(ku->kek[i]);
  free(ku->kek);
  free(ku->phi_node);
  ku->kek = NULL;
  ku->phi_node = NULL;
}

/*
 * 用户密钥：SK 含 L=g^ε、K= g^{ε+α}；z 供解密约化；
 * trace_ct = Enc_k2( |Enc_k1(id)| || id密文 || ε字节 ) 供审计追溯；
 * TK/KEK：K1 与 H(att)^{εz}、apk^{εz} 经树节点调节得到每用户 KEK。
 */
int abe_aa_keygen(pairing_t pairing, const abe_pk_t *pk, const abe_msk_t *msk, const abe_apk_t *apk,
                  const char *user_id, int n_attrs, const int *attrs, int n_attr, int user_index,
                  kek_tree_t *tree, const int *const *attr_groups, const int *attr_group_lens,
                  abe_sk_t *sk, abe_tk_t *tk, abe_kek_user_t *ku) {
  memset(sk, 0, sizeof(*sk));
  memset(tk, 0, sizeof(*tk));
  memset(ku, 0, sizeof(*ku));
  element_t eps, z, gtmp, h01v, htmp, kek_raw, inv_theta, ez;
  element_init_Zr(eps, pairing);
  element_init_Zr(z, pairing);
  element_init_Zr(ez, pairing);
  element_init_Zr(inv_theta, pairing);
  element_init_G1(gtmp, pairing);
  element_init_G1(h01v, pairing);
  element_init_G1(htmp, pairing);
  element_init_G1(kek_raw, pairing);
  element_random(eps);
  element_random(z);
  element_init_G1(sk->K, pairing);
  element_init_G1(sk->L, pairing);
  element_init_Zr(sk->z, pairing);
  element_set(sk->z, z);
  element_pow_zn(sk->L, pk->g, eps);
  element_pow_zn(gtmp, pk->g, msk->alpha);
  element_pow_zn(sk->K, pk->g, eps);
  element_mul(sk->K, sk->K, gtmp);

  /* 追溯数据链：先 k1 加密用户 id，再与 ε 拼接后用 k2 外包一层 */
  uint8_t *psi_ct = NULL;
  size_t psi_len = 0;
  if (sym_encrypt_aes256_cbc(msk->k1, (const uint8_t *)user_id, strlen(user_id), &psi_ct, &psi_len) != 0) {
    goto fail;
  }
  size_t eps_len = element_length_in_bytes(eps);
  uint8_t *eps_buf = (uint8_t *)malloc(eps_len);
  element_to_bytes(eps_buf, eps);
  uint32_t pl = (uint32_t)psi_len;
  size_t inner_len = 4 + psi_len + eps_len;
  uint8_t *inner = (uint8_t *)malloc(inner_len);
  memcpy(inner, &pl, 4);
  memcpy(inner + 4, psi_ct, psi_len);
  memcpy(inner + 4 + psi_len, eps_buf, eps_len);
  free(eps_buf);
  if (sym_encrypt_aes256_cbc(msk->k2, inner, inner_len, &sk->trace_ct, &sk->trace_len) != 0) {
    free(inner);
    free(psi_ct);
    goto fail;
  }
  free(inner);
  free(psi_ct);

  element_init_G1(tk->K1, pairing);
  tk->K_attr = (element_t *)malloc(sizeof(element_t) * (size_t)n_attrs);
  ku->kek = (element_t *)malloc(sizeof(element_t) * (size_t)n_attrs);
  ku->phi_node = (int *)malloc(sizeof(int) * (size_t)n_attrs);
  for (int a = 0; a < n_attrs; a++) {
    ku->phi_node[a] = -1;
    element_init_G1(tk->K_attr[a], pairing);
    element_set1(tk->K_attr[a]);
    element_init_G1(ku->kek[a], pairing);
    element_set1(ku->kek[a]);
  }

  h01(pairing, h01v);
  element_mul(ez, msk->alpha, eps);
  element_mul(ez, ez, z);
  element_pow_zn(tk->K1, pk->g, ez);
  element_mul(ez, eps, z);
  element_pow_zn(gtmp, h01v, ez);
  element_mul(tk->K1, tk->K1, gtmp);

  for (int i = 0; i < n_attr; i++) {
    int att = attrs[i];
    h_attr(pairing, htmp, att);
    element_mul(ez, eps, z);
    element_pow_zn(tk->K_attr[att], htmp, ez);
    element_mul(ez, eps, z);
    element_pow_zn(kek_raw, apk->t[att], ez);
    int *cover = NULL;
    int clen = 0;
    if (kek_tree_mincs(tree, attr_groups[att], attr_group_lens[att], &cover, &clen) != 0) {
      free(cover);
      goto fail;
    }
    int phi = -1;
    if (kek_tree_intersect_deepest(tree, user_index, cover, clen, &phi) != 0) {
      free(cover);
      goto fail;
    }
    free(cover);
    ku->phi_node[att] = phi;
    element_invert(inv_theta, tree->theta[phi]);
    element_pow_zn(ku->kek[att], kek_raw, inv_theta);
  }

  element_clear(eps);
  element_clear(z);
  element_clear(ez);
  element_clear(inv_theta);
  element_clear(gtmp);
  element_clear(h01v);
  element_clear(htmp);
  element_clear(kek_raw);
  return 0;
fail:
  element_clear(eps);
  element_clear(z);
  element_clear(ez);
  element_clear(inv_theta);
  element_clear(gtmp);
  element_clear(h01v);
  element_clear(htmp);
  element_clear(kek_raw);
  return -1;
}

/*
 * 加密：随机 R∈GT；由 H2(m||R) 得盲化指数 s；C=R·e(g,g)^s，Cp=g^s；
 * Crows[i] 对行 i 用属性和 M 的列装配；对称密钥由 R 经 H("symk",bytes(R)) 派生，须先将 Zr 缓冲清零再 element_to_bytes。
 */
int abe_encrypt(pairing_t pairing, const abe_pk_t *pk, const int *M, int l, int n, const int *rho,
                const uint8_t *msg, size_t msg_len, abe_ct_t *ct) {
  abe_ct_init(ct);
  ct->l = l;
  ct->n = n;
  ct->M = (int *)malloc(sizeof(int) * (size_t)(l * n));
  ct->rho = (int *)malloc(sizeof(int) * (size_t)l);
  memcpy(ct->M, M, sizeof(int) * (size_t)(l * n));
  memcpy(ct->rho, rho, sizeof(int) * (size_t)l);

  element_init_GT(ct->R, pairing);
  element_init_GT(ct->C, pairing);
  element_init_G1(ct->Cp, pairing);
  element_random(ct->R);

  element_t s, neg_s, sym_key, tmp_g, acc, hatt, hj;
  element_init_Zr(s, pairing);
  element_init_Zr(neg_s, pairing);
  element_init_Zr(sym_key, pairing);
  element_init_G1(tmp_g, pairing);
  element_init_G1(acc, pairing);
  element_init_G1(hatt, pairing);
  element_init_G1(hj, pairing);

  uint8_t rbuf[element_length_in_bytes(ct->R)];
  element_to_bytes(rbuf, ct->R);
  uint8_t *mconcat = (uint8_t *)malloc(msg_len + sizeof(rbuf));
  memcpy(mconcat, msg, msg_len);
  memcpy(mconcat + msg_len, rbuf, sizeof(rbuf));
  hash_to_zr(pairing, s, "H2mR", mconcat, msg_len + sizeof(rbuf));
  free(mconcat);

  element_neg(neg_s, s);
  element_pow_zn(ct->C, pk->e_gg, s);
  element_mul(ct->C, ct->R, ct->C);
  element_pow_zn(ct->Cp, pk->g, s);

  ct->Crows = (element_t *)malloc(sizeof(element_t) * (size_t)l);
  for (int i = 0; i < l; i++) {
    element_init_G1(ct->Crows[i], pairing);
    h_attr(pairing, hatt, rho[i]);
    element_pow_zn(ct->Crows[i], hatt, neg_s);
    element_set1(acc);
    for (int j = 0; j < n; j++) {
      int mij = M[i * n + j];
      if (mij == 0) continue;
      h_zero_col(pairing, hj, j + 1);
      element_t mijz;
      element_init_Zr(mijz, pairing);
      element_set_si(mijz, mij);
      element_mul(mijz, mijz, neg_s);
      element_pow_zn(tmp_g, hj, mijz);
      element_mul(acc, acc, tmp_g);
      element_clear(mijz);
    }
    element_mul(ct->Crows[i], ct->Crows[i], acc);
  }

  hash_to_zr(pairing, sym_key, "symk", rbuf, sizeof(rbuf));
  uint8_t k32[32];
  /* Zr 序列化长度可能小于 32，未用字节必须为 0，否则 AES 密钥与解密侧不一致 */
  memset(k32, 0, sizeof(k32));
  element_to_bytes(k32, sym_key);
  if (sym_encrypt_aes256_cbc(k32, msg, msg_len, &ct->ct_sym, &ct->ct_sym_len) != 0) {
    element_clear(s);
    element_clear(neg_s);
    element_clear(sym_key);
    element_clear(tmp_g);
    element_clear(acc);
    element_clear(hatt);
    element_clear(hj);
    return -2;
  }

  element_clear(s);
  element_clear(neg_s);
  element_clear(sym_key);
  element_clear(tmp_g);
  element_clear(acc);
  element_clear(hatt);
  element_clear(hj);
  return 0;
}

/* AM 阶段：为每属性采样 k_attr[a]，乘入对应策略行 Crows；再在辅助头结点上放出 g^(…)· 与 ask 相关的 E_hdr */
int abe_am_encrypt(pairing_t pairing, const abe_pk_t *pk, const abe_ask_t *ask, const abe_apk_t *apk,
                   kek_tree_t *tree, const int *const *attr_groups, const int *attr_group_lens,
                   abe_ct_t *ct) {
  int n_attrs = apk->n_attrs;
  ct->k_attr = (element_t *)malloc(sizeof(element_t) * (size_t)n_attrs);
  ct->E_hdr = (element_t **)calloc((size_t)n_attrs, sizeof(element_t *));
  ct->hdr_node = (int *)malloc(sizeof(int) * (size_t)n_attrs);
  ct->n_hdr = n_attrs;

  for (int a = 0; a < n_attrs; a++) {
    element_init_Zr(ct->k_attr[a], pairing);
    element_random(ct->k_attr[a]);
    ct->hdr_node[a] = -1;
  }

  element_t gk, exp_z;
  element_init_G1(gk, pairing);
  element_init_Zr(exp_z, pairing);

  for (int r = 0; r < ct->l; r++) {
    int att = ct->rho[r];
    element_pow_zn(gk, pk->g, ct->k_attr[att]);
    element_mul(ct->Crows[r], ct->Crows[r], gk);
  }

  for (int a = 0; a < n_attrs; a++) {
    int *cover = NULL;
    int clen = 0;
    if (kek_tree_mincs(tree, attr_groups[a], attr_group_lens[a], &cover, &clen) != 0) return -1;
    int vnode = cover && clen > 0 ? cover[0] : -1;
    free(cover);
    if (vnode < 0) {
      ct->E_hdr[a] = NULL;
      continue;
    }
    ct->hdr_node[a] = vnode;
    element_mul(exp_z, ct->k_attr[a], tree->theta[vnode]);
    element_div(exp_z, exp_z, ask->t[a]);
    ct->E_hdr[a] = (element_t *)malloc(sizeof(element_t));
    element_init_G1(*ct->E_hdr[a], pairing);
    element_pow_zn(*ct->E_hdr[a], pk->g, exp_z);
  }

  element_clear(gk);
  element_clear(exp_z);
  return 0;
}

/* CSP：分子含 TK 与 Cp 的配对、分母含 KEK×E_hdr；输出 tct = 外包变换后的 GT 元素 */
int abe_csp_decrypt(pairing_t pairing, const abe_pk_t *pk, const abe_apk_t *apk, const abe_ct_t *ct,
                    const abe_tk_t *tk, const abe_kek_user_t *ku, const int *auth_rows, int rn,
                    const element_t *w, element_t *tct_out) {
  (void)pk;
  (void)apk;
  element_init_GT(*tct_out, pairing);
  element_t prod_k, t2, den, num, acc, tmp_g1;
  element_init_G1(prod_k, pairing);
  element_init_G1(tmp_g1, pairing);
  element_init_GT(t2, pairing);
  element_init_GT(den, pairing);
  element_init_GT(num, pairing);
  element_init_GT(acc, pairing);
  element_set1(prod_k);
  for (int i = 0; i < rn; i++) {
    int row = auth_rows[i];
    int att = ct->rho[row];
    element_pow_zn(tmp_g1, tk->K_attr[att], w[i]);
    element_mul(prod_k, prod_k, tmp_g1);
  }
  pairing_apply(num, prod_k, ct->Cp, pairing);
  pairing_apply(t2, tk->K1, ct->Cp, pairing);
  element_mul(num, num, t2);
  element_set1(den);
  for (int i = 0; i < rn; i++) {
    int row = auth_rows[i];
    int att = ct->rho[row];
    if (!ct->E_hdr || !ct->E_hdr[att]) {
      element_clear(prod_k);
      element_clear(tmp_g1);
      element_clear(t2);
      element_clear(den);
      element_clear(num);
      element_clear(acc);
      element_clear(*tct_out);
      return -2;
    }
    element_t term;
    element_init_GT(term, pairing);
    pairing_apply(term, ku->kek[att], *ct->E_hdr[att], pairing);
    element_pow_zn(term, term, w[i]);
    element_mul(den, den, term);
    element_clear(term);
  }
  element_div(*tct_out, num, den);
  element_clear(prod_k);
  element_clear(tmp_g1);
  element_clear(t2);
  element_clear(den);
  element_clear(num);
  element_clear(acc);
  return 0;
}

/*
 * DU：先 tct^{1/z}，再用 L、Crows 与 SK 恢复 R'，仅由 R' 派生 symk 解 ct_sym。
 * 不满足策略时 R' 与加密时 R 不一致，AES 失败即返回失败；不再使用 ct->R 回退。
 */
int abe_du_decrypt(pairing_t pairing, const abe_pk_t *pk, const abe_ct_t *ct, const abe_sk_t *sk,
                   const element_t *tct, const int *auth_rows, int rn, const element_t *w,
                   uint8_t **msg_out, size_t *msg_len_out) {
  element_t zinv, tct_pow, P, tmp_g1, row_acc;
  element_init_Zr(zinv, pairing);
  element_init_GT(tct_pow, pairing);
  element_init_GT(P, pairing);
  element_init_G1(tmp_g1, pairing);
  element_init_G1(row_acc, pairing);
  element_invert(zinv, sk->z);
  element_pow_zn(tct_pow, *tct, zinv);
  element_set1(row_acc);
  for (int i = 0; i < rn; i++) {
    int row = auth_rows[i];
    element_pow_zn(tmp_g1, ct->Crows[row], w[i]);
    element_mul(row_acc, row_acc, tmp_g1);
  }
  pairing_apply(P, sk->L, row_acc, pairing);
  element_t Rp, eK;
  element_init_GT(Rp, pairing);
  element_init_GT(eK, pairing);
  element_mul(Rp, ct->C, tct_pow);
  element_mul(Rp, Rp, P);
  pairing_apply(eK, sk->K, ct->Cp, pairing);
  element_div(Rp, Rp, eK);

  /* 临时诊断：枚举若干 R' 组合，定位 DU 公式偏差。 */
  element_t tct_pow_z;
  element_init_GT(tct_pow_z, pairing);
  element_pow_zn(tct_pow_z, *tct, sk->z);
  element_t cand;
  element_init_GT(cand, pairing);
#define DIAG_EQ(label, use_mul_tct, use_mul_p, use_inv_z, use_mul_ek)                                      \
  do {                                                                                                      \
    element_set(cand, ct->C);                                                                               \
    if (use_inv_z) {                                                                                       \
      if (use_mul_tct)                                                                                     \
        element_mul(cand, cand, tct_pow_z);                                                                \
      else                                                                                                 \
        element_div(cand, cand, tct_pow_z);                                                                \
    } else {                                                                                               \
      if (use_mul_tct)                                                                                     \
        element_mul(cand, cand, tct_pow);                                                                  \
      else                                                                                                 \
        element_div(cand, cand, tct_pow);                                                                  \
    }                                                                                                      \
    if (use_mul_p)                                                                                         \
      element_mul(cand, cand, P);                                                                          \
    else                                                                                                   \
      element_div(cand, cand, P);                                                                          \
    if (use_mul_ek)                                                                                        \
      element_mul(cand, cand, eK);                                                                         \
    else                                                                                                   \
      element_div(cand, cand, eK);                                                                         \
    fprintf(stderr, "[DU DIAG] %s eqR=%d\n", label, element_cmp(cand, ct->R) == 0 ? 1 : 0);              \
  } while (0)
  DIAG_EQ("C*t(1/z)*P/eK", 1, 1, 0, 0);
  DIAG_EQ("C/t(1/z)*P/eK", 0, 1, 0, 0);
  DIAG_EQ("C*t(1/z)/P/eK", 1, 0, 0, 0);
  DIAG_EQ("C/t(1/z)/P/eK", 0, 0, 0, 0);
  DIAG_EQ("C*t(z)*P/eK", 1, 1, 1, 0);
  DIAG_EQ("C/t(z)*P/eK", 0, 1, 1, 0);
  DIAG_EQ("C*t(z)/P/eK", 1, 0, 1, 0);
  DIAG_EQ("C/t(z)/P/eK", 0, 0, 1, 0);
  DIAG_EQ("C*t(1/z)*P*eK", 1, 1, 0, 1);
  DIAG_EQ("C/t(1/z)*P*eK", 0, 1, 0, 1);
#undef DIAG_EQ
  element_clear(cand);
  element_clear(tct_pow_z);

  int rp_eq_r = (element_cmp(Rp, ct->R) == 0);
  uint8_t rbuf_rp[element_length_in_bytes(Rp)];
  uint8_t rbuf_r[element_length_in_bytes(ct->R)];
  element_to_bytes(rbuf_rp, Rp);
  element_to_bytes(rbuf_r, ct->R);
  element_t k_rp, k_r;
  element_init_Zr(k_rp, pairing);
  element_init_Zr(k_r, pairing);
  hash_to_zr(pairing, k_rp, "symk", rbuf_rp, sizeof(rbuf_rp));
  hash_to_zr(pairing, k_r, "symk", rbuf_r, sizeof(rbuf_r));
  uint8_t k32_rp[32], k32_r[32];
  memset(k32_rp, 0, sizeof(k32_rp));
  memset(k32_r, 0, sizeof(k32_r));
  element_to_bytes(k32_rp, k_rp);
  element_to_bytes(k32_r, k_r);
  uint8_t *diag_pt = NULL;
  size_t diag_len = 0;
  int rc_rp = sym_decrypt_aes256_cbc(k32_rp, ct->ct_sym, ct->ct_sym_len, &diag_pt, &diag_len);
  if (rc_rp == 0) free(diag_pt);
  diag_pt = NULL;
  diag_len = 0;
  int rc_r = sym_decrypt_aes256_cbc(k32_r, ct->ct_sym, ct->ct_sym_len, &diag_pt, &diag_len);
  if (rc_r == 0) free(diag_pt);
  fprintf(stderr, "[DU DIAG] Rp==R ? %d\n", rp_eq_r ? 1 : 0);
  fprintf(stderr, "[DU DIAG] dec_by_Rp=%d dec_by_R=%d\n", rc_rp, rc_r);
  element_clear(k_rp);
  element_clear(k_r);

  uint8_t rbuf[element_length_in_bytes(Rp)];
  element_to_bytes(rbuf, Rp);
  element_t sym_key;
  element_init_Zr(sym_key, pairing);
  hash_to_zr(pairing, sym_key, "symk", rbuf, sizeof(rbuf));
  uint8_t k32[32];
  memset(k32, 0, sizeof(k32));
  element_to_bytes(k32, sym_key);
  if (sym_decrypt_aes256_cbc(k32, ct->ct_sym, ct->ct_sym_len, msg_out, msg_len_out) != 0) {
    element_clear(zinv);
    element_clear(tct_pow);
    element_clear(P);
    element_clear(tmp_g1);
    element_clear(row_acc);
    element_clear(Rp);
    element_clear(eK);
    element_clear(sym_key);
    return -1;
  }
  element_clear(zinv);
  element_clear(tct_pow);
  element_clear(P);
  element_clear(tmp_g1);
  element_clear(row_acc);
  element_clear(Rp);
  element_clear(eK);
  element_clear(sym_key);
  return 0;
}

/* 验证用户私钥结构：K 应等于 L · g^α（G1 内乘法） */
int abe_keycheck(pairing_t pairing, const abe_pk_t *pk, const abe_msk_t *msk, const abe_sk_t *sk) {
  (void)msk;
  element_t rhs;
  element_init_G1(rhs, pairing);
  element_mul(rhs, sk->L, pk->g_alpha);
  int ok = element_cmp(sk->K, rhs) == 0;
  element_clear(rhs);
  return ok ? 1 : 0;
}

/* 逆向 trace_ct：k2 → 内层 → k1 得到 user_id 明文字符串 */
int abe_trace(pairing_t pairing, const abe_pk_t *pk, const abe_msk_t *msk, const abe_sk_t *sk,
              char *id_out, size_t id_out_len) {
  (void)pairing;
  (void)pk;
  uint8_t *inner = NULL;
  size_t inner_len = 0;
  if (sym_decrypt_aes256_cbc(msk->k2, sk->trace_ct, sk->trace_len, &inner, &inner_len) != 0) return -1;
  if (inner_len < 4) {
    free(inner);
    return -2;
  }
  uint32_t pl = 0;
  memcpy(&pl, inner, 4);
  if (inner_len < 4 + pl) {
    free(inner);
    return -3;
  }
  uint8_t *psi_ct = inner + 4;
  uint8_t *id_pt = NULL;
  size_t id_len = 0;
  if (sym_decrypt_aes256_cbc(msk->k1, psi_ct, pl, (uint8_t **)&id_pt, &id_len) != 0) {
    free(inner);
    return -4;
  }
  if (id_len >= id_out_len) {
    free(inner);
    free(id_pt);
    return -5;
  }
  memcpy(id_out, id_pt, id_len);
  id_out[id_len] = '\0';
  free(inner);
  free(id_pt);
  return 0;
}
