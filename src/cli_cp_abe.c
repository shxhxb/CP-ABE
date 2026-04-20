/*
 * cp_abe_cli —— CLI 组装层：不负责配对公式，只调用 abe_core / abe_state / abe_ct_pack / lsss。
 *
 * 【建议阅读顺序 —— 与 init → keygen → encrypt → decrypt 数据流一致】
 *   ① cmd_init     内存里 AASetup + AMSetup + kek_tree_build，再写入 state_dir
 *   ② cmd_keygen   load_state → abe_aa_keygen → users/<id>/{sk,tk,ku}.bin
 *   ③ cmd_encrypt  lsss_build_matrix_and → abe_encrypt → abe_am_encrypt → abe_ct_save(.ct)
 *   ④ cmd_decrypt  abe_ct_load → lsss_recover(w) → abe_csp_decrypt → abe_du_decrypt
 *   ⑤ cmd_trace    泄露 sk.bin + load_state → abe_trace（依赖 MSK 与 keygen 时 trace_ct）
 *   ⑥ cmd_revoke   追加 revoked.txt；decrypt 前 is_revoked（工程黑名单，非密文重加密）
 *
 * 算法细节对照 abe_core.c；群元素定长编码见 abe_io.c。策略：AND(attr0,attr1)；
 * policy_attr_groups 必须与 keygen/encrypt 一致。学完主路径后可看 cmd_demo、cmd_roundtrip_bin。
 */
#include "abe_core.h"
#include "abe_ct_pack.h"
#include "abe_state.h"
#include "kek_tree.h"
#include "lsss.h"
#include <pbc/pbc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <direct.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
/*
 * Windows 下路径来源可能是 UTF-8（GUI 传参）或系统 ANSI（终端输入）；
 * 这里依次尝试 UTF-8/ACP 转宽字符后 _wfopen，最后再回退窄字符 fopen。
 */
static FILE *cp_fopen_utf8(const char *path, const char *mode) {
  wchar_t wpath[4096];
  wchar_t wmode[32];
  FILE *f = NULL;
  if (!path || !mode) return NULL;

  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, mode, -1, wmode, (int)(sizeof(wmode) / sizeof(wmode[0]))) ==
      0) {
    if (MultiByteToWideChar(CP_ACP, 0, mode, -1, wmode, (int)(sizeof(wmode) / sizeof(wmode[0]))) == 0) {
      return fopen(path, mode);
    }
  }

  if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, path, -1, wpath, (int)(sizeof(wpath) / sizeof(wpath[0]))) >
      0) {
    f = _wfopen(wpath, wmode);
    if (f) return f;
  }
  if (MultiByteToWideChar(CP_ACP, 0, path, -1, wpath, (int)(sizeof(wpath) / sizeof(wpath[0]))) > 0) {
    f = _wfopen(wpath, wmode);
    if (f) return f;
  }
  return fopen(path, mode);
}
#else
#include <sys/stat.h>
#include <sys/types.h>
static FILE *cp_fopen_utf8(const char *path, const char *mode) { return fopen(path, mode); }
#endif

#define CP_N_ATTRS 2
#define CP_MAX_USERS 16

/* 侧车 .json 用 UTF-8 二进制写入，避免 Win 下 fopen("w")+fprintf 走 ANSI 导致 Python 按 UTF-8 读失败 */
static void json_write_escaped_string(FILE *f, const char *s) {
  fputc('"', f);
  if (!s) {
    fputc('"', f);
    return;
  }
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    unsigned char c = *p;
    switch (c) {
      case '\\':
        fputs("\\\\", f);
        break;
      case '"':
        fputs("\\\"", f);
        break;
      case '\b':
        fputs("\\b", f);
        break;
      case '\f':
        fputs("\\f", f);
        break;
      case '\n':
        fputs("\\n", f);
        break;
      case '\r':
        fputs("\\r", f);
        break;
      case '\t':
        fputs("\\t", f);
        break;
      default:
        if (c < 0x20u)
          fprintf(f, "\\u%04x", (unsigned)c);
        else
          fputc((int)c, f);
        break;
    }
  }
  fputc('"', f);
}

static void write_sidecar_json_utf8(const char *jsonpath, const char *owner, const char *source_label, const char *state,
                                    const char *cipher_file) {
  FILE *jf = cp_fopen_utf8(jsonpath, "wb");
  if (!jf) return;
  fputs("{\n  \"format\": \"cpabe-core-v1\",\n  \"policy\": \"AND(attr0,attr1)\",\n"
        "  \"owner_label\": ",
        jf);
  json_write_escaped_string(jf, owner ? owner : "");
  fputs(",\n  \"source_name\": ", jf);
  json_write_escaped_string(jf, source_label ? source_label : "");
  fputs(",\n  \"state_dir\": ", jf);
  json_write_escaped_string(jf, state ? state : "");
  fputs(",\n  \"cipher_file\": ", jf);
  json_write_escaped_string(jf, cipher_file ? cipher_file : "");
  fputs("\n}\n", jf);
  fclose(jf);
}

static void path_join(char *out, size_t outsz, const char *a, const char *b) {
#ifdef _WIN32
  snprintf(out, outsz, "%s\\%s", a, b);
#else
  snprintf(out, outsz, "%s/%s", a, b);
#endif
}

static void path_join3(char *out, size_t outsz, const char *a, const char *b, const char *c) {
#ifdef _WIN32
  snprintf(out, outsz, "%s\\%s\\%s", a, b, c);
#else
  snprintf(out, outsz, "%s/%s/%s", a, b, c);
#endif
}

static int read_meta_int(const char *path, const char *key, int *out) {
  FILE *f = fopen(path, "r");
  if (!f) return -1;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    char *p = strstr(line, key);
    if (p == line) {
      p += strlen(key);
      if (*p == '=') {
        p++;
        *out = atoi(p);
        fclose(f);
        return 0;
      }
    }
  }
  fclose(f);
  return -1;
}

static int write_meta(const char *path, int n_users, int rbits, int qbits) {
  FILE *f = fopen(path, "w");
  if (!f) return -1;
  fprintf(f, "n_attrs=%d\n", CP_N_ATTRS);
  fprintf(f, "n_users=%d\n", n_users);
  fprintf(f, "rbits=%d\n", rbits);
  fprintf(f, "qbits=%d\n", qbits);
  fprintf(f, "policy=AND(attr0,attr1)\n");
  fclose(f);
  return 0;
}

/* 解密前查名单；与 abe_core 内密码学无关，见 cmd_revoke */
static int is_revoked(const char *state, const char *uid) {
  char p[512];
  path_join(p, sizeof(p), state, "revoked.txt");
  FILE *f = fopen(p, "r");
  if (!f) return 0;
  char line[256];
  while (fgets(line, sizeof(line), f)) {
    size_t n = strcspn(line, "\r\n");
    line[n] = '\0';
    if (strcmp(line, uid) == 0) {
      fclose(f);
      return 1;
    }
  }
  fclose(f);
  return 0;
}

typedef struct {
  pairing_t pairing;
  pbc_param_t param;
  abe_pk_t pk;
  abe_msk_t msk;
  abe_apk_t apk;
  abe_ask_t ask;
  kek_tree_t tree;
  int n_users;
  int loaded;
} Glob;

/* 一次「已 init 的状态目录」在内存中的快照；encrypt/decrypt/trace 均先 load_state 再办事 */

static void glob_clear(Glob *g) {
  if (!g->loaded) return;
  abe_am_clear(&g->apk, &g->ask);
  kek_tree_clear(&g->tree);
  abe_aa_clear(&g->pk, &g->msk);
  pairing_clear(g->pairing);
  pbc_param_clear(g->param);
  g->loaded = 0;
}

/* 读 state.meta → pairing.param → pk/msk/apk/ask/tree；失败码供调试（-1 meta … -7 n_attrs） */
static int load_state(const char *state, Glob *g) {
  memset(g, 0, sizeof(*g));
  char p[512];
  path_join(p, sizeof(p), state, "state.meta");
  int rbits = 160, qbits = 512;
  (void)read_meta_int(p, "rbits", &rbits);
  (void)read_meta_int(p, "qbits", &qbits);
  if (read_meta_int(p, "n_users", &g->n_users) != 0) return -1;

  path_join(p, sizeof(p), state, "pairing.param");
  if (abe_state_load_param(p, g->param) != 0) return -2;
  pairing_init_pbc_param(g->pairing, g->param);

  path_join(p, sizeof(p), state, "pk.bin");
  FILE *fp = fopen(p, "rb");
  if (!fp) return -3;
  if (abe_state_load_pk(g->pairing, &g->pk, fp) != 0) {
    fclose(fp);
    return -3;
  }
  fclose(fp);

  path_join(p, sizeof(p), state, "msk.bin");
  fp = fopen(p, "rb");
  if (!fp) return -4;
  if (abe_state_load_msk(g->pairing, &g->msk, fp) != 0) {
    fclose(fp);
    return -4;
  }
  fclose(fp);

  char pask[512];
  path_join(p, sizeof(p), state, "apk.bin");
  path_join(pask, sizeof(pask), state, "ask.bin");
  FILE *fa = fopen(p, "rb");
  FILE *fs = fopen(pask, "rb");
  if (!fa || !fs) {
    if (fa) fclose(fa);
    if (fs) fclose(fs);
    return -5;
  }
  if (abe_state_load_apk_ask(g->pairing, &g->apk, &g->ask, fa, fs) != 0) {
    fclose(fa);
    fclose(fs);
    return -5;
  }
  fclose(fa);
  fclose(fs);

  path_join(p, sizeof(p), state, "tree.bin");
  fp = fopen(p, "rb");
  if (!fp) return -6;
  if (abe_state_load_tree(g->pairing, &g->tree, fp) != 0) {
    fclose(fp);
    return -6;
  }
  fclose(fp);

  if (g->apk.n_attrs != CP_N_ATTRS) return -7;
  g->loaded = 1;
  return 0;
}

static void build_full_groups(int n_users, int *gbuf) {
  for (int i = 0; i < n_users; i++) gbuf[i] = i;
}

/*
 * 与 main.c 一致：2 用户时 attr0 覆盖 {0}、attr1 覆盖 {0,1}；
 * 更多用户时两属性均覆盖全体下标（广播 KEK 需要与 keygen 一致）。
 */
static int g_demo_g0[] = {0};
static int g_demo_g1_two[] = {0, 1};
static int g_all_buf[CP_MAX_USERS];

static void policy_attr_groups(int n_users, const int **out_g0, int *out_len0, const int **out_g1, int *out_len1) {
  if (n_users == 2) {
    *out_g0 = g_demo_g0;
    *out_len0 = 1;
    *out_g1 = g_demo_g1_two;
    *out_len1 = 2;
  } else {
    build_full_groups(n_users, g_all_buf);
    *out_g0 = g_all_buf;
    *out_g1 = g_all_buf;
    *out_len0 = n_users;
    *out_len1 = n_users;
  }
}

/*
 * init：建目录 + 写 meta；内存中生成全套公共参数与秘密，再序列化到磁盘（与 demo 逻辑相同，多了一步持久化）。
 */
static int cmd_init(const char *state, int rbits, int qbits, int n_users) {
  if (n_users <= 0 || n_users > CP_MAX_USERS) {
    fprintf(stderr, "n_users must be 1..%d\n", CP_MAX_USERS);
    return 1;
  }
#ifdef _WIN32
  (void)_mkdir(state);
#else
  (void)mkdir(state, 0755);
#endif

  char p[512];
  path_join(p, sizeof(p), state, "state.meta");
  if (write_meta(p, n_users, rbits, qbits) != 0) return 1;

  /* Type A 配对 + AA/AM/KEK 树；clear 前必须把树与密钥写到 tree.bin 等文件 */
  pairing_t pairing;
  pbc_param_t param;
  pbc_param_init_a_gen(param, rbits, qbits);
  pairing_init_pbc_param(pairing, param);

  abe_pk_t pk;
  abe_msk_t msk;
  if (abe_aa_setup(pairing, &pk, &msk) != 0) {
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  abe_apk_t apk;
  abe_ask_t ask;
  if (abe_am_setup(pairing, &pk, &apk, &ask, CP_N_ATTRS) != 0) {
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  kek_tree_t tree;
  if (kek_tree_build(&tree, pairing, n_users) != 0) {
    abe_am_clear(&apk, &ask);
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }

  path_join(p, sizeof(p), state, "pairing.param");
  if (abe_state_save_param(p, param) != 0) goto fail;

  path_join(p, sizeof(p), state, "pk.bin");
  FILE *f = fopen(p, "wb");
  if (!f) goto fail;
  if (abe_state_save_pk(f, &pk) != 0) {
    fclose(f);
    goto fail;
  }
  fclose(f);

  path_join(p, sizeof(p), state, "msk.bin");
  f = fopen(p, "wb");
  if (!f) goto fail;
  if (abe_state_save_msk(f, &msk) != 0) {
    fclose(f);
    goto fail;
  }
  fclose(f);

  char pask_init[512];
  path_join(p, sizeof(p), state, "apk.bin");
  path_join(pask_init, sizeof(pask_init), state, "ask.bin");
  FILE *fa = fopen(p, "wb");
  FILE *fs = fopen(pask_init, "wb");
  if (!fa || !fs) {
    if (fa) fclose(fa);
    if (fs) fclose(fs);
    goto fail;
  }
  if (abe_state_save_apk_ask(fa, fs, &apk, &ask) != 0) {
    fclose(fa);
    fclose(fs);
    goto fail;
  }
  fclose(fa);
  fclose(fs);

  path_join(p, sizeof(p), state, "tree.bin");
  f = fopen(p, "wb");
  if (!f) goto fail;
  if (abe_state_save_tree(f, &tree) != 0) {
    fclose(f);
    goto fail;
  }
  fclose(f);

  path_join(p, sizeof(p), state, "revoked.txt");
  f = fopen(p, "wb");
  if (f) fclose(f);

  kek_tree_clear(&tree);
  abe_am_clear(&apk, &ask);
  abe_aa_clear(&pk, &msk);
  pairing_clear(pairing);
  pbc_param_clear(param);
  printf("OK init state=%s n_users=%d\n", state, n_users);
  return 0;
fail:
  kek_tree_clear(&tree);
  abe_am_clear(&apk, &ask);
  abe_aa_clear(&pk, &msk);
  pairing_clear(pairing);
  pbc_param_clear(param);
  return 1;
}

/* 将 user_id 映射为安全目录名（users/<safe>/），非法字符改为 '_' */

static void sanitize_uid(const char *in, char *out, size_t osz) {
  size_t j = 0;
  for (size_t i = 0; in[i] && j + 1 < osz; i++) {
    unsigned char c = (unsigned char)in[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' ||
        c == '.')
      out[j++] = (char)c;
    else
      out[j++] = '_';
  }
  out[j] = '\0';
}

static int ensure_users_dir(const char *state) {
  char p[512];
#ifdef _WIN32
  path_join(p, sizeof(p), state, "users");
  (void)_mkdir(p);
#else
  snprintf(p, sizeof(p), "%s/users", state);
  (void)mkdir(p, 0755);
#endif
  return 0;
}

/*
 * keygen：user_index ∈ [0, n_users)；policy_attr_groups 必须与后续 encrypt 相同，否则 AM 头与用户 KEK 对不齐。
 */
static int cmd_keygen(const char *state, const char *user_id, int user_index) {
  Glob g;
  int e = load_state(state, &g);
  if (e != 0) {
    fprintf(stderr, "load_state failed %d\n", e);
    return 1;
  }
  if (user_index < 0 || user_index >= g.n_users) {
    fprintf(stderr, "user_index out of range 0..%d\n", g.n_users - 1);
    glob_clear(&g);
    return 1;
  }
  const int *ga0 = NULL, *ga1 = NULL;
  int ln0 = 0, ln1 = 0;
  policy_attr_groups(g.n_users, &ga0, &ln0, &ga1, &ln1);
  const int *gps[CP_N_ATTRS] = {ga0, ga1};
  int glen[CP_N_ATTRS] = {ln0, ln1};
  int attrs[] = {0, 1};

  abe_sk_t sk;
  abe_tk_t tk;
  abe_kek_user_t ku;
  if (abe_aa_keygen(g.pairing, &g.pk, &g.msk, &g.apk, user_id, CP_N_ATTRS, attrs, 2, user_index, &g.tree, gps,
                    glen, &sk, &tk, &ku) != 0) {
    fprintf(stderr, "abe_aa_keygen failed\n");
    glob_clear(&g);
    return 1;
  }
  ensure_users_dir(state);
  char safe[128];
  sanitize_uid(user_id, safe, sizeof(safe));
  char base[512];
#ifdef _WIN32
  path_join3(base, sizeof(base), state, "users", safe);
  (void)_mkdir(base);
#else
  snprintf(base, sizeof(base), "%s/users/%s", state, safe);
  (void)mkdir(base, 0755);
#endif

  char p[640];
  path_join(p, sizeof(p), base, "sk.bin");
  FILE *f = fopen(p, "wb");
  if (!f || abe_state_save_sk(f, &sk) != 0) {
    fprintf(stderr, "save sk failed\n");
    if (f) fclose(f);
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    return 1;
  }
  fclose(f);

  path_join(p, sizeof(p), base, "tk.bin");
  f = fopen(p, "wb");
  if (!f || abe_state_save_tk(f, &tk, CP_N_ATTRS) != 0) {
    fprintf(stderr, "save tk failed\n");
    if (f) fclose(f);
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    return 1;
  }
  fclose(f);

  path_join(p, sizeof(p), base, "ku.bin");
  f = fopen(p, "wb");
  if (!f || abe_state_save_ku(f, &ku, CP_N_ATTRS) != 0) {
    fprintf(stderr, "save ku failed\n");
    if (f) fclose(f);
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    return 1;
  }
  fclose(f);

  path_join(p, sizeof(p), base, "index.txt");
  f = fopen(p, "w");
  if (f) {
    fprintf(f, "%d\n", user_index);
    fclose(f);
  }

  abe_sk_clear(g.pairing, &sk);
  abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
  abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
  glob_clear(&g);
  printf("OK keygen user=%s index=%d\n", safe, user_index);
  return 0;
}

static uint8_t *read_whole_file(const char *path, size_t *len_out) {
  FILE *f = cp_fopen_utf8(path, "rb");
  if (!f) return NULL;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0 || n > (long)(64 << 20)) {
    fclose(f);
    return NULL;
  }
  uint8_t *buf = (uint8_t *)malloc((size_t)n + 1);
  if (!buf) {
    fclose(f);
    return NULL;
  }
  if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
    free(buf);
    fclose(f);
    return NULL;
  }
  fclose(f);
  buf[n] = 0;
  *len_out = (size_t)n;
  return buf;
}

/*
 * encrypt：明文进 abe_encrypt（得 R、C、Cp、Crows、AES 载荷）；abe_am_encrypt 注入每属性 k_attr 与 E_hdr。
 * owner/source_label 仅写入 .ct.json 方便 GUI/人读，不参与配对运算。
 */
static int cmd_encrypt(const char *state, const char *inpath, const char *outpath, const char *owner,
                       const char *source_label) {
  Glob g;
  if (load_state(state, &g) != 0) {
    fprintf(stderr, "load_state failed\n");
    return 1;
  }
  size_t plen = 0;
  uint8_t *plain = read_whole_file(inpath, &plen);
  if (!plain) {
    fprintf(stderr, "read plaintext failed: %s\n", inpath ? inpath : "");
    glob_clear(&g);
    return 1;
  }
  const int *ga0 = NULL, *ga1 = NULL;
  int ln0 = 0, ln1 = 0;
  policy_attr_groups(g.n_users, &ga0, &ln0, &ga1, &ln1);
  const int *gps[CP_N_ATTRS] = {ga0, ga1};
  int glen[CP_N_ATTRS] = {ln0, ln1};

  int M[64];
  int l = 0, n = 0;
  /* rho[i] 为第 i 行绑定的属性下标；AND(2) 时为 {0,1} */
  if (lsss_build_matrix_and(CP_N_ATTRS, M, &l, &n) != 0) {
    free(plain);
    glob_clear(&g);
    return 1;
  }
  int rho[] = {0, 1};
  abe_ct_t ct;
  abe_ct_init(&ct);
  if (abe_encrypt(g.pairing, &g.pk, M, l, n, rho, plain, plen, &ct) != 0) {
    free(plain);
    fprintf(stderr, "abe_encrypt failed\n");
    glob_clear(&g);
    return 1;
  }
  free(plain);
  if (abe_am_encrypt(g.pairing, &g.pk, &g.ask, &g.apk, &g.tree, gps, glen, &ct) != 0) {
    abe_ct_clear(g.pairing, &ct);
    fprintf(stderr, "abe_am_encrypt failed\n");
    glob_clear(&g);
    return 1;
  }

  FILE *fo = cp_fopen_utf8(outpath, "wb");
  if (!fo || abe_ct_save(g.pairing, &ct, fo) != 0) {
    fprintf(stderr, "save ct failed: %s\n", outpath ? outpath : "");
    if (fo) fclose(fo);
    abe_ct_clear(g.pairing, &ct);
    glob_clear(&g);
    return 1;
  }
  fclose(fo);
  abe_ct_clear(g.pairing, &ct);

  char jsonpath[520];
  snprintf(jsonpath, sizeof(jsonpath), "%s.json", outpath);
  write_sidecar_json_utf8(jsonpath, owner ? owner : "", source_label ? source_label : "", state, outpath);

  glob_clear(&g);
  printf("OK encrypt -> %s\n", outpath);
  return 0;
}

/* 从 state/users/<id>/ 读 sk、tk、ku；与 cmd_keygen 写入路径对称 */

static int load_user_keys(Glob *g, const char *state, const char *user_id, abe_sk_t *sk, abe_tk_t *tk,
                          abe_kek_user_t *ku) {
  char safe[128];
  sanitize_uid(user_id, safe, sizeof(safe));
  char udir[512];
  path_join3(udir, sizeof(udir), state, "users", safe);
  char p[640];
  path_join(p, sizeof(p), udir, "sk.bin");
  FILE *f = fopen(p, "rb");
  if (!f) return -1;
  if (abe_state_load_sk(g->pairing, sk, f) != 0) {
    fclose(f);
    return -2;
  }
  fclose(f);
  path_join(p, sizeof(p), udir, "tk.bin");
  f = fopen(p, "rb");
  if (!f) {
    abe_sk_clear(g->pairing, sk);
    return -3;
  }
  if (abe_state_load_tk(g->pairing, tk, CP_N_ATTRS, f) != 0) {
    fclose(f);
    abe_sk_clear(g->pairing, sk);
    return -3;
  }
  fclose(f);
  path_join(p, sizeof(p), udir, "ku.bin");
  f = fopen(p, "rb");
  if (!f) {
    abe_sk_clear(g->pairing, sk);
    abe_tk_clear(g->pairing, tk, CP_N_ATTRS);
    return -4;
  }
  if (abe_state_load_ku(g->pairing, ku, CP_N_ATTRS, f) != 0) {
    fclose(f);
    abe_sk_clear(g->pairing, sk);
    abe_tk_clear(g->pairing, tk, CP_N_ATTRS);
    return -4;
  }
  fclose(f);
  return 0;
}

/*
 * decrypt：auth_rows={0,1} 表示「两行策略都满足」；先 lsss_recover 得 w，再 CSP（外包）得 tct，DU 用 sk+z 解对称密文。
 */
static int cmd_decrypt(const char *state, const char *user_id, const char *inpath, const char *outpath) {
  if (is_revoked(state, user_id)) {
    fprintf(stderr, "user revoked by AA policy list\n");
    return 1;
  }
  Glob g;
  if (load_state(state, &g) != 0) {
    fprintf(stderr, "load_state failed\n");
    return 1;
  }
  abe_sk_t sk;
  abe_tk_t tk;
  abe_kek_user_t ku;
  memset(&sk, 0, sizeof(sk));
  memset(&tk, 0, sizeof(tk));
  memset(&ku, 0, sizeof(ku));
  if (load_user_keys(&g, state, user_id, &sk, &tk, &ku) != 0) {
    fprintf(stderr, "load user keys failed (run keygen first)\n");
    glob_clear(&g);
    return 1;
  }

  FILE *fi = cp_fopen_utf8(inpath, "rb");
  if (!fi) {
    fprintf(stderr, "cannot open ciphertext: %s\n", inpath ? inpath : "");
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    return 1;
  }
  abe_ct_t ct;
  abe_ct_init(&ct);
  if (abe_ct_load(g.pairing, &ct, fi) != 0) {
    fclose(fi);
    abe_ct_clear(g.pairing, &ct);
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    return 1;
  }
  fclose(fi);

  int auth_rows[] = {0, 1};
  element_t w[2];
  element_init_Zr(w[0], g.pairing);
  element_init_Zr(w[1], g.pairing);
  if (lsss_recover(g.pairing, ct.M, ct.l, ct.n, auth_rows, 2, w) != 0) {
    element_clear(w[0]);
    element_clear(w[1]);
    abe_ct_clear(g.pairing, &ct);
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    return 1;
  }
  element_t tct;
  if (abe_csp_decrypt(g.pairing, &g.pk, &g.apk, &ct, &tk, &ku, auth_rows, 2, w, &tct) != 0) {
    element_clear(w[0]);
    element_clear(w[1]);
    /* CSP 失败路径内已 element_clear(tct) */
    abe_ct_clear(g.pairing, &ct);
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    fprintf(stderr, "CSP decrypt failed\n");
    return 1;
  }
  uint8_t *out = NULL;
  size_t olen = 0;
  if (abe_du_decrypt(g.pairing, &g.pk, &ct, &sk, &tct, auth_rows, 2, w, &out, &olen) != 0) {
    element_clear(w[0]);
    element_clear(w[1]);
    element_clear(tct);
    abe_ct_clear(g.pairing, &ct);
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    fprintf(stderr, "DU decrypt failed (AES key mismatch: use same state as encrypt; do not re-run init after encrypt; "
                      "keygen user before encrypt)\n");
    return 1;
  }
  FILE *fo = cp_fopen_utf8(outpath, "wb");
  if (!fo || fwrite(out, 1, olen, fo) != olen) {
    free(out);
    element_clear(w[0]);
    element_clear(w[1]);
    element_clear(tct);
    abe_ct_clear(g.pairing, &ct);
    abe_sk_clear(g.pairing, &sk);
    abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
    abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
    glob_clear(&g);
    fprintf(stderr, "write output failed: %s\n", outpath ? outpath : "");
    return 1;
  }
  fclose(fo);
  free(out);
  element_clear(w[0]);
  element_clear(w[1]);
  element_clear(tct);
  abe_ct_clear(g.pairing, &ct);
  abe_sk_clear(g.pairing, &sk);
  abe_tk_clear(g.pairing, &tk, CP_N_ATTRS);
  abe_kek_clear(g.pairing, &ku, CP_N_ATTRS);
  glob_clear(&g);
  printf("OK decrypt -> %s\n", outpath);
  return 0;
}

/* trace：用 MSK 解开 sk.trace_ct（keygen 时封装）；仅需 sk 二进制，不需 tk/ku */

static int cmd_trace(const char *state, const char *skpath) {
  Glob g;
  if (load_state(state, &g) != 0) {
    fprintf(stderr, "load_state failed\n");
    return 1;
  }
  FILE *f = cp_fopen_utf8(skpath, "rb");
  if (!f) {
    fprintf(stderr, "open sk failed: %s\n", skpath ? skpath : "");
    glob_clear(&g);
    return 1;
  }
  abe_sk_t sk;
  memset(&sk, 0, sizeof(sk));
  if (abe_state_load_sk(g.pairing, &sk, f) != 0) {
    fclose(f);
    fprintf(stderr, "load sk failed\n");
    glob_clear(&g);
    return 1;
  }
  fclose(f);
  char id[256];
  if (abe_trace(g.pairing, &g.pk, &g.msk, &sk, id, sizeof(id)) != 0) {
    abe_sk_clear(g.pairing, &sk);
    glob_clear(&g);
    fprintf(stderr, "trace failed\n");
    return 1;
  }
  abe_sk_clear(g.pairing, &sk);
  glob_clear(&g);
  printf("TRACE_ID %s\n", id);
  return 0;
}

/* revoke：追加一行 uid；无密钥更新、无密文变换，与论文中「密码学撤销」可能不同 */

static int cmd_revoke(const char *state, const char *user_id) {
  char p[512];
  path_join(p, sizeof(p), state, "revoked.txt");
  FILE *f = fopen(p, "a");
  if (!f) return 1;
  fprintf(f, "%s\n", user_id);
  fclose(f);
  printf("OK revoke recorded %s\n", user_id);
  return 0;
}

/* demo：不落盘，单进程内存跑通 Setup→Encrypt→Decrypt→Trace；便于对照 abe_core 阅读 */

static int cmd_demo(const char *user_id, const char *msg) {
  pairing_t pairing;
  pbc_param_t param;
  pbc_param_init_a_gen(param, 160, 512);
  pairing_init_pbc_param(pairing, param);
  abe_pk_t pk;
  abe_msk_t msk;
  if (abe_aa_setup(pairing, &pk, &msk) != 0) return 1;
  abe_apk_t apk;
  abe_ask_t ask;
  if (abe_am_setup(pairing, &pk, &apk, &ask, CP_N_ATTRS) != 0) {
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  kek_tree_t tree;
  if (kek_tree_build(&tree, pairing, 2) != 0) {
    abe_am_clear(&apk, &ask);
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  int g0[] = {0};
  int g1[] = {0, 1};
  const int *gps_kg[] = {g0, g1};
  int glen_kg[] = {1, 2};
  int attrs[] = {0, 1};
  abe_sk_t sk;
  abe_tk_t tk;
  abe_kek_user_t ku;
  if (abe_aa_keygen(pairing, &pk, &msk, &apk, user_id, CP_N_ATTRS, attrs, 2, 0, &tree, gps_kg, glen_kg,
                    &sk, &tk, &ku) != 0) {
    kek_tree_clear(&tree);
    abe_am_clear(&apk, &ask);
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  if (!abe_keycheck(pairing, &pk, &msk, &sk)) {
    fprintf(stderr, "KeyCheck failed\n");
    abe_kek_clear(pairing, &ku, CP_N_ATTRS);
    abe_tk_clear(pairing, &tk, CP_N_ATTRS);
    abe_sk_clear(pairing, &sk);
    kek_tree_clear(&tree);
    abe_am_clear(&apk, &ask);
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  int M[64];
  int l = 0, n = 0;
  lsss_build_matrix_and(2, M, &l, &n);
  int rho[] = {0, 1};
  abe_ct_t ct;
  const uint8_t *m = (const uint8_t *)msg;
  size_t ml = strlen(msg) + 1;
  if (abe_encrypt(pairing, &pk, M, l, n, rho, m, ml, &ct) != 0) {
    abe_kek_clear(pairing, &ku, CP_N_ATTRS);
    abe_tk_clear(pairing, &tk, CP_N_ATTRS);
    abe_sk_clear(pairing, &sk);
    kek_tree_clear(&tree);
    abe_am_clear(&apk, &ask);
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  const int *gps_am[] = {g0, g1};
  int glen_am[] = {1, 2};
  if (abe_am_encrypt(pairing, &pk, &ask, &apk, &tree, gps_am, glen_am, &ct) != 0) {
    abe_ct_clear(pairing, &ct);
    abe_kek_clear(pairing, &ku, CP_N_ATTRS);
    abe_tk_clear(pairing, &tk, CP_N_ATTRS);
    abe_sk_clear(pairing, &sk);
    kek_tree_clear(&tree);
    abe_am_clear(&apk, &ask);
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  int auth_rows[] = {0, 1};
  element_t w[2];
  element_init_Zr(w[0], pairing);
  element_init_Zr(w[1], pairing);
  lsss_recover(pairing, M, l, n, auth_rows, 2, w);
  element_t tct;
  abe_csp_decrypt(pairing, &pk, &apk, &ct, &tk, &ku, auth_rows, 2, w, &tct);
  uint8_t *out = NULL;
  size_t ol = 0;
  abe_du_decrypt(pairing, &pk, &ct, &sk, &tct, auth_rows, 2, w, &out, &ol);
  printf("decrypted (%zu bytes): %.*s\n", ol, (int)ol, out);
  char traced[128];
  abe_trace(pairing, &pk, &msk, &sk, traced, sizeof(traced));
  printf("trace id: %s\n", traced);
  free(out);
  element_clear(w[0]);
  element_clear(w[1]);
  element_clear(tct);
  abe_ct_clear(pairing, &ct);
  abe_kek_clear(pairing, &ku, CP_N_ATTRS);
  abe_tk_clear(pairing, &tk, CP_N_ATTRS);
  abe_sk_clear(pairing, &sk);
  kek_tree_clear(&tree);
  abe_am_clear(&apk, &ask);
  abe_aa_clear(&pk, &msk);
  pairing_clear(pairing);
  pbc_param_clear(param);
  printf("OK\n");
  return 0;
}

/* 自检：abe_ct_save/load（CTB5 v6）后仍能通过 CSP+DU，验证 abe_io 与 ct 打包 */
static int cmd_roundtrip_bin(void) {
  pairing_t pairing;
  pbc_param_t param;
  pbc_param_init_a_gen(param, 160, 512);
  pairing_init_pbc_param(pairing, param);
  abe_pk_t pk;
  abe_msk_t msk;
  if (abe_aa_setup(pairing, &pk, &msk) != 0) return 1;
  abe_apk_t apk;
  abe_ask_t ask;
  if (abe_am_setup(pairing, &pk, &apk, &ask, CP_N_ATTRS) != 0) {
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  kek_tree_t tree;
  if (kek_tree_build(&tree, pairing, 2) != 0) {
    abe_am_clear(&apk, &ask);
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  const int *ga0 = NULL, *ga1 = NULL;
  int ln0 = 0, ln1 = 0;
  policy_attr_groups(2, &ga0, &ln0, &ga1, &ln1);
  const int *gps[] = {ga0, ga1};
  int glen[] = {ln0, ln1};
  int attrs[] = {0, 1};
  abe_sk_t sk;
  abe_tk_t tk;
  abe_kek_user_t ku;
  if (abe_aa_keygen(pairing, &pk, &msk, &apk, "u", CP_N_ATTRS, attrs, 2, 0, &tree, gps, glen, &sk, &tk, &ku) != 0) {
    kek_tree_clear(&tree);
    abe_am_clear(&apk, &ask);
    abe_aa_clear(&pk, &msk);
    pairing_clear(pairing);
    pbc_param_clear(param);
    return 1;
  }
  int M[64];
  int l = 0, n = 0;
  lsss_build_matrix_and(2, M, &l, &n);
  int rho[] = {0, 1};
  const uint8_t *msg = (const uint8_t *)"hi";
  abe_ct_t ct;
  abe_ct_init(&ct);
  if (abe_encrypt(pairing, &pk, M, l, n, rho, msg, 3, &ct) != 0) goto bad;
  if (abe_am_encrypt(pairing, &pk, &ask, &apk, &tree, gps, glen, &ct) != 0) goto bad;

  {
    int ar[] = {0, 1};
    element_t ww[2];
    element_init_Zr(ww[0], pairing);
    element_init_Zr(ww[1], pairing);
    lsss_recover(pairing, ct.M, ct.l, ct.n, ar, 2, ww);
    element_t tt;
    if (abe_csp_decrypt(pairing, &pk, &apk, &ct, &tk, &ku, ar, 2, ww, &tt) != 0) {
      fprintf(stderr, "mem CSP fail\n");
      element_clear(ww[0]);
      element_clear(ww[1]);
      goto bad;
    }
    uint8_t *oo = NULL;
    size_t oo_len = 0;
    if (abe_du_decrypt(pairing, &pk, &ct, &sk, &tt, ar, 2, ww, &oo, &oo_len) != 0) {
      fprintf(stderr, "mem DU fail (before file io)\n");
      element_clear(ww[0]);
      element_clear(ww[1]);
      element_clear(tt);
      goto bad;
    }
    free(oo);
    element_clear(ww[0]);
    element_clear(ww[1]);
    element_clear(tt);
  }

  FILE *tmp = fopen("_ct_rt.bin", "wb+");
  if (!tmp || abe_ct_save(pairing, &ct, tmp) != 0) goto bad;
  fflush(tmp);
  rewind(tmp);
  abe_ct_clear(pairing, &ct);
  if (abe_ct_load(pairing, &ct, tmp) != 0) {
    fprintf(stderr, "roundtrip load ct failed\n");
    fclose(tmp);
    goto bad2;
  }
  fclose(tmp);

  int auth_rows[] = {0, 1};
  element_t w[2];
  element_init_Zr(w[0], pairing);
  element_init_Zr(w[1], pairing);
  lsss_recover(pairing, ct.M, ct.l, ct.n, auth_rows, 2, w);
  element_t tct;
  if (abe_csp_decrypt(pairing, &pk, &apk, &ct, &tk, &ku, auth_rows, 2, w, &tct) != 0) {
    fprintf(stderr, "roundtrip CSP fail\n");
    element_clear(w[0]);
    element_clear(w[1]);
    abe_ct_clear(pairing, &ct);
    goto bad2;
  }
  uint8_t *out = NULL;
  size_t ol = 0;
  if (abe_du_decrypt(pairing, &pk, &ct, &sk, &tct, auth_rows, 2, w, &out, &ol) != 0) {
    fprintf(stderr, "roundtrip DU fail\n");
    element_clear(w[0]);
    element_clear(w[1]);
    element_clear(tct);
    abe_ct_clear(pairing, &ct);
    goto bad2;
  }
  printf("roundtrip OK out=%.*s\n", (int)ol, out);
  free(out);
  element_clear(w[0]);
  element_clear(w[1]);
  element_clear(tct);
  abe_ct_clear(pairing, &ct);
  abe_kek_clear(pairing, &ku, CP_N_ATTRS);
  abe_tk_clear(pairing, &tk, CP_N_ATTRS);
  abe_sk_clear(pairing, &sk);
  kek_tree_clear(&tree);
  abe_am_clear(&apk, &ask);
  abe_aa_clear(&pk, &msk);
  pairing_clear(pairing);
  pbc_param_clear(param);
  remove("_ct_rt.bin");
  return 0;
bad:
  abe_ct_clear(pairing, &ct);
bad2:
  abe_kek_clear(pairing, &ku, CP_N_ATTRS);
  abe_tk_clear(pairing, &tk, CP_N_ATTRS);
  abe_sk_clear(pairing, &sk);
  kek_tree_clear(&tree);
  abe_am_clear(&apk, &ask);
  abe_aa_clear(&pk, &msk);
  pairing_clear(pairing);
  pbc_param_clear(param);
  return 1;
}

/* 子命令分派入口；具体逻辑均在 static cmd_* */

static void usage(void) {
  fprintf(stderr,
          "Usage:\n"
          "  cp_abe_cli init <state_dir> [rbits] [qbits] [n_users]\n"
          "  cp_abe_cli keygen <state_dir> <user_id> <user_index>\n"
          "  cp_abe_cli encrypt <state_dir> <infile> <out.ct> <owner> <source_name>\n"
          "  cp_abe_cli decrypt <state_dir> <user_id> <in.ct> <outfile>\n"
          "  cp_abe_cli trace <state_dir> <leaked_sk.bin>\n"
          "  cp_abe_cli revoke <state_dir> <user_id>\n"
          "  cp_abe_cli demo [user_id] [message]\n"
          "  cp_abe_cli roundtrip-bin   (self-test ct serialize)\n");
}

int main(int argc, char **argv) {
  /* 无密码学；仅解析 argv 并调用对应 cmd_* */
  if (argc < 2) {
    usage();
    return 1;
  }
  const char *cmd = argv[1];
  if (strcmp(cmd, "init") == 0) {
    if (argc < 3) return 1;
    int r = argc > 3 ? atoi(argv[3]) : 160;
    int q = argc > 4 ? atoi(argv[4]) : 512;
    int nu = argc > 5 ? atoi(argv[5]) : CP_MAX_USERS;
    return cmd_init(argv[2], r, q, nu);
  }
  if (strcmp(cmd, "keygen") == 0) {
    if (argc < 5) return 1;
    return cmd_keygen(argv[2], argv[3], atoi(argv[4]));
  }
  if (strcmp(cmd, "encrypt") == 0) {
    if (argc < 7) return 1;
    return cmd_encrypt(argv[2], argv[3], argv[4], argv[5], argv[6]);
  }
  if (strcmp(cmd, "decrypt") == 0) {
    if (argc < 6) return 1;
    return cmd_decrypt(argv[2], argv[3], argv[4], argv[5]);
  }
  if (strcmp(cmd, "trace") == 0) {
    if (argc < 4) return 1;
    return cmd_trace(argv[2], argv[3]);
  }
  if (strcmp(cmd, "revoke") == 0) {
    if (argc < 4) return 1;
    return cmd_revoke(argv[2], argv[3]);
  }
  if (strcmp(cmd, "demo") == 0) {
    const char *uid = argc >= 3 ? argv[2] : "user_alice";
    const char *msg = argc >= 4 ? argv[3] : "hello-cp-abe-guo2023";
    return cmd_demo(uid, msg);
  }
  if (strcmp(cmd, "roundtrip-bin") == 0) return cmd_roundtrip_bin();
  usage();
  return 1;
}
