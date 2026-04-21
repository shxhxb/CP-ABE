#ifndef ABE_CORE_H
#define ABE_CORE_H

/*
 * CP-ABE（郭文等）双授权结构示意：
 *   AA  —— 系统主密钥 MSK / 公钥 PK
 *   AM  —— 各属性的秘密 ask[a] 与公钥 apk[a]=g^{ask[a]}
 * 密文由「属性 LSSS 一次一密部分」+「对称封装」+「AM 加密的 KEK 头」组成；
 * 解密分两阶段：外包 CSP 用 TK/KEK 得到中间分量 tct；用户 DU 用 SK 恢复明文。
 *
 * 【与 cp_abe_cli 同序啃读】abe_aa_setup → abe_am_setup → abe_aa_keygen → abe_encrypt →
 * abe_am_encrypt →（解密侧）lsss_recover → abe_csp_decrypt → abe_du_decrypt；追溯见 abe_trace。
 */

#include <stddef.h>
#include <pbc/pbc.h>
#include "kek_tree.h"

/* 授权机构 AA 的公钥：g、g^α、e(g,g)、以及仅 AA/MSK 持有的对称密钥（追溯用） */
typedef struct {
  element_t g;
  element_t g_alpha;
  element_t e_gg;
  uint8_t k1[32];
  uint8_t k2[32];
} abe_pk_t;

/* 主密钥：α ∈ Zr；k1/k2 与 PK 中对应，用于加密用户身份与内部追溯载荷 */
typedef struct {
  element_t alpha;
  uint8_t k1[32];
  uint8_t k2[32];
} abe_msk_t;

/* 属性权威 AM：每个属性 a 的公开参数 t[a] ∈ G1（由秘密 ask[a] 生成） */
typedef struct {
  int n_attrs;
  element_t *t;
} abe_apk_t;

/* AM 秘密：ask[a] ∈ Zr，满足 apk[a] = g^{ask[a]} */
typedef struct {
  int n_attrs;
  element_t *t;
} abe_ask_t;

/*
 * 用户私钥（DU 持有）：K,L ∈ G1，z ∈ Zr；trace_ct 为用 MSK 加密封装的 (用户 id + ε)，
 * 供 AA 在泄密后解密追溯。
 */
typedef struct {
  element_t K;
  element_t L;
  element_t z;
  uint8_t *trace_ct;
  size_t trace_len;
} abe_sk_t;

/* 转换密钥 TK（托管给 CSP）：外包解密用，与属性相关的 K_attr[] 及全局 K1 */
typedef struct {
  element_t K1;
  element_t *K_attr;
} abe_tk_t;

/*
 * 每用户每属性的 KEK：沿 KEK 树把组密钥调节到用户可解的节点；
 * phi_node[a] 为该用户在属性 a 上的交汇节点（覆盖与用户路径最深交点）。
 */
typedef struct {
  element_t *kek;
  int *phi_node;
} abe_kek_user_t;

/*
 * 密文：LSSS 矩阵 M（l×n）、行到属性 rho[]；
 * R∈GT,C∈GT,Cp∈G1,Crows[] 对应论文中线性秘密共享与盲化；
 * ct_sym 为用 R 派生的 AES-256 密钥加密的消息；
 * k_attr、E_hdr、hdr_node 为 AM 侧对每个属性注入的随机量及加密头。
 */
typedef struct {
  int l, n;
  int *M;
  int *rho;
  element_t R;
  element_t C;
  element_t Cp;
  element_t *Crows;
  uint8_t *ct_sym;
  size_t ct_sym_len;
  element_t *k_attr;
  element_t **E_hdr;
  int *hdr_node;
  int n_hdr;
} abe_ct_t;

/* AA：生成 (PK, MSK)，采样 α、g，计算 g^α、e(g,g) */
int abe_aa_setup(pairing_t pairing, abe_pk_t *pk, abe_msk_t *msk);
void abe_aa_clear(abe_pk_t *pk, abe_msk_t *msk);

/* AM：为每个属性采样 ask[a]， apk[a]=g^{ask[a]} */
int abe_am_setup(pairing_t pairing, const abe_pk_t *pk, abe_apk_t *apk, abe_ask_t *ask, int n_attrs);
void abe_am_clear(abe_apk_t *apk, abe_ask_t *ask);

/* AA+AM 协作用户密钥：输出 SK、TK、各属性 KEK（依赖 KEK 树覆盖与用户 leaf） */
int abe_aa_keygen(pairing_t pairing, const abe_pk_t *pk, const abe_msk_t *msk, const abe_apk_t *apk,
                  const char *user_id, int n_attrs, const int *attrs, int n_attr, int user_index,
                  kek_tree_t *tree, const int *const *attr_groups, const int *attr_group_lens,
                  abe_sk_t *sk, abe_tk_t *tk, abe_kek_user_t *ku);

void abe_sk_clear(pairing_t pairing, abe_sk_t *sk);
void abe_tk_clear(pairing_t pairing, abe_tk_t *tk, int n_attrs);
void abe_kek_clear(pairing_t pairing, abe_kek_user_t *ku, int n_attrs);

void abe_ct_init(abe_ct_t *ct);
void abe_ct_clear(pairing_t pairing, abe_ct_t *ct);

/* 加密（AA 侧核心）：LSSS 下生成 R,s，构造 C,Cp,Crows[]，并对消息做对称封装 */
int abe_encrypt(pairing_t pairing, const abe_pk_t *pk, const int *M, int l, int n, const int *rho,
                const uint8_t *msg, size_t msg_len, abe_ct_t *ct);

/* AM 后处理：行盲化 + 每属性产生 E_hdr（KEK 头） */
int abe_am_encrypt(pairing_t pairing, const abe_pk_t *pk, const abe_ask_t *ask, const abe_apk_t *apk,
                   kek_tree_t *tree, const int *const *attr_groups, const int *attr_group_lens,
                   abe_ct_t *ct);

/* 属性撤销：对未撤销用户的属性群密钥执行 UpKEK（KEK_i <- KEK_i^sigma） */
int abe_upkek(pairing_t pairing, abe_kek_user_t *ku, int attr_idx, const element_t sigma);

/* 属性撤销：对密文执行 AMReEncrypt（E_hdr[attr] <- E_hdr[attr]^(1/sigma)） */
int abe_am_reencrypt(pairing_t pairing, abe_ct_t *ct, int attr_idx, const element_t sigma);

/* CSP 外包解密：用 TK+KEK 与 LSSS 系数 w 得到中间量 tct ∈ GT */
int abe_csp_decrypt(pairing_t pairing, const abe_pk_t *pk, const abe_apk_t *apk, const abe_ct_t *ct,
                    const abe_tk_t *tk, const abe_kek_user_t *ku, const int *auth_rows, int rn,
                    const element_t *w, element_t *tct_out);

/* DU 本地解密：用 SK 与 tct 恢复与加密时一致的 R'，派生 AES 密钥解 ct_sym */
int abe_du_decrypt(pairing_t pairing, const abe_pk_t *pk, const abe_ct_t *ct, const abe_sk_t *sk,
                   const element_t *tct, const int *auth_rows, int rn, const element_t *w,
                   uint8_t **msg_out, size_t *msg_len_out);

/* 检测 SK 是否满足群内关系 K = L · g^α（与用户 id 无关的结构校验） */
int abe_keycheck(pairing_t pairing, const abe_pk_t *pk, const abe_msk_t *msk, const abe_sk_t *sk);

/* AA 用 MSK 追溯：解密 trace_ct 链恢复 user_id */
int abe_trace(pairing_t pairing, const abe_pk_t *pk, const abe_msk_t *msk, const abe_sk_t *sk,
              char *id_out, size_t id_out_len);

#endif
