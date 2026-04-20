/*
 * AND 策略：构造 LSSS 矩阵 M；lsss_recover 在解密侧由 cmd_decrypt 调用，
 * 输入 auth_rows（满足的行号）输出系数 w，供 CSP/DU 配对运算使用。
 */
#include "lsss.h"
#include <stdlib.h>
#include <string.h>

int lsss_build_matrix_and(int n_attrs, int *M_out, int *l_out, int *n_out) {
  if (n_attrs <= 0 || !M_out) return -1;
  int l = n_attrs;
  int n = n_attrs;
  for (int i = 0; i < l; i++)
    for (int j = 0; j < n; j++) M_out[i * n + j] = 0;
  for (int i = 0; i < n_attrs; i++) {
    M_out[i * n + i] = 1;
    if (i + 1 < n_attrs) M_out[i * n + (i + 1)] = 1;
  }
  *l_out = l;
  *n_out = n;
  return 0;
}

static void gauss_zr(pairing_t pairing, element_t **A, int n_eq, int n_var) {
  int cols = n_var + 1;
  for (int c = 0; c < n_var; c++) {
    int piv = -1;
    for (int r = c; r < n_eq; r++) {
      if (!element_is0(A[r][c])) {
        piv = r;
        break;
      }
    }
    if (piv < 0) continue;
    if (piv != c) {
      for (int k = c; k < cols; k++) {
        element_t tmp;
        element_init_Zr(tmp, pairing);
        element_set(tmp, A[c][k]);
        element_set(A[c][k], A[piv][k]);
        element_set(A[piv][k], tmp);
        element_clear(tmp);
      }
    }
    element_t inv;
    element_init_Zr(inv, pairing);
    element_invert(inv, A[c][c]);
    for (int k = c; k < cols; k++) element_mul(A[c][k], A[c][k], inv);
    element_clear(inv);
    for (int r = 0; r < n_eq; r++) {
      if (r == c) continue;
      if (!element_is0(A[r][c])) {
        element_t fac;
        element_init_Zr(fac, pairing);
        element_set(fac, A[r][c]);
        for (int k = c; k < cols; k++) {
          element_t t;
          element_init_Zr(t, pairing);
          element_mul(t, A[c][k], fac);
          element_sub(A[r][k], A[r][k], t);
          element_clear(t);
        }
        element_clear(fac);
      }
    }
  }
}

int lsss_recover(pairing_t pairing, const int *M, int l, int n, const int *auth_rows, int rn,
                 element_t *w) {
  if (!M || !auth_rows || rn <= 0 || !w) return -1;
  int n_eq = n;
  int n_var = rn;
  int cols = n_var + 1;
  element_t **A = (element_t **)malloc(sizeof(element_t *) * (size_t)n_eq);
  for (int j = 0; j < n_eq; j++) {
    A[j] = (element_t *)malloc(sizeof(element_t) * (size_t)cols);
    for (int k = 0; k < cols; k++) {
      element_init_Zr(A[j][k], pairing);
      element_set0(A[j][k]);
    }
  }
  for (int j = 0; j < n; j++) {
    for (int k = 0; k < rn; k++) {
      element_set_si(A[j][k], M[auth_rows[k] * n + j]);
    }
  }
  element_t one, zero;
  element_init_Zr(one, pairing);
  element_init_Zr(zero, pairing);
  element_set1(one);
  element_set0(zero);
  for (int j = 0; j < n; j++) {
    if (j == 0)
      element_set(A[j][n_var], one);
    else
      element_set(A[j][n_var], zero);
  }
  element_clear(one);
  element_clear(zero);

  gauss_zr(pairing, A, n_eq, n_var);

  for (int i = 0; i < rn; i++) element_set(w[i], A[i][n_var]);

  for (int j = 0; j < n_eq; j++) {
    for (int k = 0; k < cols; k++) element_clear(A[j][k]);
    free(A[j]);
  }
  free(A);
  return 0;
}
