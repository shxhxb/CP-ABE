#ifndef ABE_STATE_H
#define ABE_STATE_H

#include "abe_core.h"
#include "kek_tree.h"
#include <pbc/pbc.h>
#include <stdio.h>

/* 元素序列化使用文本 snprint/set_str（与早期 binary 不兼容） */
#define ABE_STATE_MAGIC_PK 0x32304B50u  /* 'PK02' */
#define ABE_STATE_MAGIC_MS 0x3230534du  /* 'MS02' */
#define ABE_STATE_MAGIC_AP 0x32305041u  /* 'AP02' */
#define ABE_STATE_MAGIC_AS 0x32305341u  /* 'AS02' */
#define ABE_STATE_MAGIC_KT 0x3230544bu  /* 'KT02' */
#define ABE_STATE_MAGIC_SK 0x32304b53u  /* 'SK02' */
#define ABE_STATE_MAGIC_TK 0x32304b54u  /* 'TK02' */
#define ABE_KU_MAGIC 0x3230554bu         /* 'KU02' */

int abe_state_save_param(const char *path, pbc_param_t param);
int abe_state_load_param(const char *path, pbc_param_t param);

int abe_state_save_pk(FILE *f, const abe_pk_t *pk);
int abe_state_load_pk(pairing_t pairing, abe_pk_t *pk, FILE *f);

int abe_state_save_msk(FILE *f, const abe_msk_t *msk);
int abe_state_load_msk(pairing_t pairing, abe_msk_t *msk, FILE *f);

int abe_state_save_apk_ask(FILE *fapk, FILE *fask, const abe_apk_t *apk, const abe_ask_t *ask);
int abe_state_load_apk_ask(pairing_t pairing, abe_apk_t *apk, abe_ask_t *ask, FILE *fapk, FILE *fask);

int abe_state_save_tree(FILE *f, const kek_tree_t *t);
int abe_state_load_tree(pairing_t pairing, kek_tree_t *t, FILE *f);

int abe_state_save_sk(FILE *f, const abe_sk_t *sk);
int abe_state_load_sk(pairing_t pairing, abe_sk_t *sk, FILE *f);

int abe_state_save_tk(FILE *f, const abe_tk_t *tk, int n_attrs);
int abe_state_load_tk(pairing_t pairing, abe_tk_t *tk, int n_attrs, FILE *f);

int abe_state_save_ku(FILE *f, const abe_kek_user_t *ku, int n_attrs);
int abe_state_load_ku(pairing_t pairing, abe_kek_user_t *ku, int n_attrs, FILE *f);

#endif
