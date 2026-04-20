/*
 * 以下为程序总览（非「每行一个功能」）：最小端到端演示流程说明。
 * 最小端到端演示：AASetup → AMSetup → KEK树 → AAKeyGen → KeyCheck
 * → LSSS(AND 策略) → Encrypt → AMEncrypt → LSSS 恢复系数 w
 * → CSPDecrypt → DUDecrypt → Trace。
 * 参数 a 类型由 pbc_param_init_a_gen 指定； argv[1]=user_id，argv[2]=明文字符串。
 * 带磁盘状态与多子命令的完整路径见 cli_cp_abe.c（init→keygen→encrypt→decrypt）。
 * 其下源码每行尾部注释：功能简述 + 声明所在头文件（工程内实现多在同名 .c）。
 */
#include "abe_core.h"   /* abe_* 类型与函数 */
#include "crypto_utils.h" /* 本 demo 未直接调用；abe_core 内部使用 */
#include "lsss.h"       /* lsss_* */
#include <pbc/pbc.h>    /* pairing_t, element_t, pbc_* , element_* */
#include <stdio.h>      /* printf, fprintf, stderr */
#include <stdlib.h>     /* free */
#include <string.h>     /* strlen, memcmp */

int main(int argc, char **argv) { /* 程序入口；argc/argv 为标准 C 命令行（无单独头文件） */
  pairing_t pairing; /* 配对上下文类型；PBC 库 pbc.h */
  pbc_param_t param; /* 配对参数字柄；PBC 库 pbc.h */
  pbc_param_init_a_gen(param, 160, 512); /* 生成 Type A 曲线参数；PBC 库 pbc.h */
  pairing_init_pbc_param(pairing, param); /* 由 param 初始化 pairing；PBC 库 pbc.h */

  /* 本 demo：2 个属性，AND 需两行全满足；user_index=0 对应 KEK 树叶 */
  const char *user_id = "user_alice"; /* 默认用户 id 字符串字面量 */
  const char *msg_str = "hello-cp-abe-guo2023"; /* 默认明文字符串 */
  if (argc >= 2 && argv[1] && argv[1][0] != '\0') user_id = argv[1]; /* 可选：第 1 参数覆盖 user_id */
  if (argc >= 3 && argv[2] && argv[2][0] != '\0') msg_str = argv[2]; /* 可选：第 2 参数覆盖消息 */

  abe_pk_t pk; /* AA 公钥结构体；abe_core.h，abe_aa_setup 等在 abe_core.c */
  abe_msk_t msk; /* AA 主密钥；abe_core.h / abe_core.c */
  if (abe_aa_setup(pairing, &pk, &msk) != 0) { /* AA 系统建立；abe_core.h / abe_core.c */
    fprintf(stderr, "AASetup failed\n"); /* 写错误流；stdio.h */
    return 1; /* 失败退出码 */
  }

  const int n_attrs = 2; /* 属性个数，与 AND 两行一致 */
  abe_apk_t apk; /* AM 公钥（每属性 t[a]）；abe_core.h / abe_core.c */
  abe_ask_t ask; /* AM 私钥 ask；abe_core.h / abe_core.c */
  if (abe_am_setup(pairing, &pk, &apk, &ask, n_attrs) != 0) { /* AM 建立；abe_core.h / abe_core.c */
    fprintf(stderr, "AMSetup failed\n"); /* stdio.h */
    return 1;
  }

  kek_tree_t tree; /* KEK 二叉树；kek_tree.h / kek_tree.c */
  if (kek_tree_build(&tree, pairing, 2) != 0) { /* 为 2 个用户位建树；kek_tree.h / kek_tree.c */
    fprintf(stderr, "KEK tree failed\n"); /* stdio.h */
    return 1;
  }

  int g0[] = {0}; /* 属性 0 策略覆盖的用户下标集合（演示） */
  int g1[] = {0, 1}; /* 属性 1 覆盖的下标 */
  const int *groups[2] = {g0, g1}; /* 每属性一组用户索引，传入 keygen/am_encrypt */
  int glen[2] = {1, 2}; /* 各组长度 */

  abe_sk_t sk; /* 用户私钥；abe_core.h / abe_core.c */
  abe_tk_t tk; /* 转换密钥（CSP）；abe_core.h / abe_core.c */
  abe_kek_user_t ku; /* 用户 KEK 分量；abe_core.h / abe_core.c */
  int attrs[] = {0, 1}; /* 用户持有的属性下标列表 */
  if (abe_aa_keygen(pairing, &pk, &msk, &apk, user_id, n_attrs, attrs, 2, 0, &tree, groups, glen, /* keygen 参数续行 */
                    &sk, &tk, &ku) != 0) { /* 输出 sk/tk/ku；abe_aa_keygen：abe_core.h / abe_core.c */
    fprintf(stderr, "AAKeyGen failed\n"); /* stdio.h */
    return 1;
  }

  if (!abe_keycheck(pairing, &pk, &msk, &sk)) { /* 校验 K 与 L·g^α 一致；abe_core.h / abe_core.c */
    fprintf(stderr, "KeyCheck failed\n"); /* stdio.h */
    return 1;
  }

  int M[4]; /* LSSS 矩阵展平缓冲（2×2 AND）；栈上数组 */
  int l = 0, n = 0; /* 矩阵行数、列数，由 lsss_build_matrix_and 写出 */
  lsss_build_matrix_and(2, M, &l, &n); /* 构造 AND(2) 的 M；lsss.h / lsss.c */
  int rho[] = {0, 1}; /* 第 i 行绑定属性 rho[i] */
  abe_ct_t ct; /* 密文结构；abe_core.h */
  const uint8_t *msg = (const uint8_t *)msg_str; /* 明文字节指针 */
  size_t msg_len = strlen(msg_str) + 1; /* 长度含字符串末尾 NUL；strlen 在 string.h */
  if (abe_encrypt(pairing, &pk, M, l, n, rho, msg, msg_len, &ct) != 0) { /* AA 侧加密；abe_core.h / abe_core.c */
    fprintf(stderr, "Encrypt failed\n"); /* stdio.h */
    return 1;
  }

  if (abe_am_encrypt(pairing, &pk, &ask, &apk, &tree, groups, glen, &ct) != 0) { /* AM 侧加密头；abe_core.h / abe_core.c */
    fprintf(stderr, "AMEncrypt failed\n"); /* stdio.h */
    return 1;
  }

  int auth_rows[] = {0, 1}; /* 解密时使用的策略行（两行 AND 均满足） */
  element_t w[2]; /* LSSS 恢复系数，Zr 元素；pbc.h */
  element_init_Zr(w[0], pairing); /* 初始化 Zr 元素；PBC pbc.h */
  element_init_Zr(w[1], pairing); /* PBC pbc.h */
  if (lsss_recover(pairing, M, l, n, auth_rows, 2, w) != 0) { /* 解线性方程得 w；lsss.h / lsss.c */
    fprintf(stderr, "LSSS recover failed\n"); /* stdio.h */
    return 1;
  }

  element_t tct; /* CSP 外包解密输出的 GT 中间量；pbc.h */
  if (abe_csp_decrypt(pairing, &pk, &apk, &ct, &tk, &ku, auth_rows, 2, w, &tct) != 0) { /* CSP 阶段；abe_core.h / abe_core.c */
    fprintf(stderr, "CSPDecrypt failed\n"); /* stdio.h */
    return 1;
  }

  uint8_t *out = NULL; /* DU 解密得到的明文缓冲指针 */
  size_t out_len = 0; /* 明文长度 */
  if (abe_du_decrypt(pairing, &pk, &ct, &sk, &tct, auth_rows, 2, w, &out, &out_len) != 0) { /* DU 阶段；abe_core.h / abe_core.c */
    fprintf(stderr, "DUDecrypt failed\n"); /* stdio.h */
    return 1;
  }

  printf("decrypted (%zu bytes): %.*s\n", out_len, (int)out_len, out); /* 打印明文；stdio.h */
  if (out_len != msg_len || memcmp(out, msg, out_len) != 0) { /* 与加密前比对；string.h */
    fprintf(stderr, "plaintext mismatch\n"); /* stdio.h */
    return 1;
  }

  char traced[128]; /* 追溯输出的用户 id 缓冲 */
  if (abe_trace(pairing, &pk, &msk, &sk, traced, sizeof(traced)) != 0) { /* 从 sk 解 trace_ct；abe_core.h / abe_core.c */
    fprintf(stderr, "Trace failed\n"); /* stdio.h */
    return 1;
  }
  printf("trace id: %s\n", traced); /* stdio.h */

  free(out); /* 释放 abe_du_decrypt 分配的明文；stdlib.h */
  element_clear(w[0]); /* 释放 Zr 元素；PBC pbc.h */
  element_clear(w[1]); /* PBC pbc.h */
  element_clear(tct); /* 释放 GT 元素；PBC pbc.h */
  abe_ct_clear(pairing, &ct); /* 释放密文内所有 element 与缓冲；abe_core.h / abe_core.c */
  abe_kek_clear(pairing, &ku, n_attrs); /* 释放 ku；abe_core.h / abe_core.c */
  abe_tk_clear(pairing, &tk, n_attrs); /* 释放 tk；abe_core.h / abe_core.c */
  abe_sk_clear(pairing, &sk); /* 释放 sk；abe_core.h / abe_core.c */
  kek_tree_clear(&tree); /* 释放 KEK 树；kek_tree.h / kek_tree.c */
  abe_am_clear(&apk, &ask); /* 释放 AM 密钥材料；abe_core.h / abe_core.c */
  abe_aa_clear(&pk, &msk); /* 释放 pk/msk 中群元素；abe_core.h / abe_core.c */
  pairing_clear(pairing); /* 释放配对；PBC pbc.h */
  pbc_param_clear(param); /* 释放曲线参数；PBC pbc.h */
  printf("OK\n"); /* stdio.h */
  return 0; /* 成功退出码 */
} /* main 函数结束 */
