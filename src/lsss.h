#ifndef LSSS_H
#define LSSS_H

/*
 * 访问结构 → LSSS 矩阵 M（此处仅实现 AND 链的构造）;
 * recover：在已知授权行 auth_rows 上解 M^T w = (1,0,…)^T 得到权重 w，供配对乘幂用。
 */
#include <pbc/pbc.h>

int lsss_recover(pairing_t pairing, const int *M, int l, int n, const int *auth_rows, int rn,
                 element_t *w);

int lsss_build_matrix_and(int n_attrs, int *M_out, int *l_out, int *n_out);

#endif
