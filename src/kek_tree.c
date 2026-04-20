/*
 * 满二叉树 KEK：mincs 求属性组覆盖的节点集，intersect_deepest 得用户交汇节点；
 * keygen 定 ku、encrypt 定 E_hdr 均依赖同一棵树（见 abe_aa_keygen / abe_am_encrypt）。
 */
#include "kek_tree.h"
#include <stdlib.h>
#include <string.h>

static void assign_thetas(kek_tree_t *t, pairing_t pairing) {
  t->theta = (element_t *)malloc(sizeof(element_t) * (size_t)t->n_nodes);
  for (int i = 0; i < t->n_nodes; i++) {
    element_init_Zr(t->theta[i], pairing);
    element_random(t->theta[i]);
  }
}

static int build_recursive(kek_tree_t *t, int lo, int hi, int parent) {
  int id = t->n_nodes++;
  t->nodes[id].id = id;
  t->nodes[id].parent = parent;
  t->nodes[id].left = -1;
  t->nodes[id].right = -1;
  t->nodes[id].leaf_user = -1;
  if (lo == hi) {
    t->nodes[id].leaf_user = lo;
    if (lo < t->n_users) t->leaf_of_user[lo] = id;
    return id;
  }
  int mid = (lo + hi) / 2;
  int lch = build_recursive(t, lo, mid, id);
  int rch = build_recursive(t, mid + 1, hi, id);
  t->nodes[id].left = lch;
  t->nodes[id].right = rch;
  return id;
}

static int count_leaves(int n_users) {
  int n = 1;
  while (n < n_users) n <<= 1;
  return n;
}

int kek_tree_build(kek_tree_t *t, pairing_t pairing, int num_users) {
  if (num_users <= 0) return -1;
  memset(t, 0, sizeof(*t));
  t->n_users = num_users;
  t->leaf_of_user = (int *)malloc(sizeof(int) * (size_t)num_users);
  if (!t->leaf_of_user) return -2;
  for (int i = 0; i < num_users; i++) t->leaf_of_user[i] = -1;
  int nleaf = count_leaves(num_users);
  int est_nodes = nleaf * 2 + 4;
  t->nodes = (kt_node_t *)calloc((size_t)est_nodes, sizeof(kt_node_t));
  if (!t->nodes) {
    free(t->leaf_of_user);
    return -3;
  }
  t->n_nodes = 0;
  t->root = build_recursive(t, 0, nleaf - 1, -1);
  assign_thetas(t, pairing);
  return 0;
}

void kek_tree_clear(kek_tree_t *t) {
  if (t->theta) {
    for (int i = 0; i < t->n_nodes; i++) element_clear(t->theta[i]);
    free(t->theta);
    t->theta = NULL;
  }
  free(t->nodes);
  free(t->leaf_of_user);
  t->nodes = NULL;
  t->leaf_of_user = NULL;
  t->n_nodes = 0;
}

int kek_tree_path(const kek_tree_t *t, int user_id, int **path_out, int *path_len) {
  if (user_id < 0 || user_id >= t->n_users) return -1;
  int leaf = t->leaf_of_user[user_id];
  if (leaf < 0) return -2;
  int cap = 32;
  int *p = (int *)malloc(sizeof(int) * (size_t)cap);
  int n = 0;
  int cur = leaf;
  while (cur >= 0) {
    if (n >= cap) {
      cap *= 2;
      p = (int *)realloc(p, sizeof(int) * (size_t)cap);
    }
    p[n++] = cur;
    cur = t->nodes[cur].parent;
  }
  *path_out = p;
  *path_len = n;
  return 0;
}

static int leaf_in_subtree(const kek_tree_t *t, int node, int leaf_node_id) {
  if (node < 0) return 0;
  if (t->nodes[node].leaf_user >= 0) return node == leaf_node_id;
  return leaf_in_subtree(t, t->nodes[node].left, leaf_node_id) ||
         leaf_in_subtree(t, t->nodes[node].right, leaf_node_id);
}

static int user_in_subtree(const kek_tree_t *t, int node, int user_id) {
  if (user_id < 0 || user_id >= t->n_users) return 0;
  int lf = t->leaf_of_user[user_id];
  if (lf < 0) return 0;
  return leaf_in_subtree(t, node, lf);
}

static int any_user_outside_group_in_subtree(const kek_tree_t *t, int node, const int *grp, int gn) {
  for (int u = 0; u < t->n_users; u++) {
    int in = 0;
    for (int j = 0; j < gn; j++)
      if (grp[j] == u) {
        in = 1;
        break;
      }
    if (in) continue;
    if (user_in_subtree(t, node, u)) return 1;
  }
  return 0;
}

static int all_group_users_in_subtree(const kek_tree_t *t, int node, const int *grp, int gn) {
  for (int i = 0; i < gn; i++)
    if (!user_in_subtree(t, node, grp[i])) return 0;
  return 1;
}

static void mincs_rec(const kek_tree_t *t, int node, const int *grp, int gn, int **out, int *olen, int *ocap) {
  if (node < 0 || gn <= 0) return;
  if (t->nodes[node].leaf_user >= 0) {
    int lu = t->nodes[node].leaf_user;
    if (lu >= t->n_users) return;
    for (int i = 0; i < gn; i++)
      if (grp[i] == lu) {
        if (*olen >= *ocap) {
          *ocap *= 2;
          *out = (int *)realloc(*out, sizeof(int) * (size_t)*ocap);
        }
        (*out)[(*olen)++] = node;
        return;
      }
    return;
  }
  if (!all_group_users_in_subtree(t, node, grp, gn)) return;
  if (!any_user_outside_group_in_subtree(t, node, grp, gn)) {
    if (*olen >= *ocap) {
      *ocap *= 2;
      *out = (int *)realloc(*out, sizeof(int) * (size_t)*ocap);
    }
    (*out)[(*olen)++] = node;
    return;
  }
  mincs_rec(t, t->nodes[node].left, grp, gn, out, olen, ocap);
  mincs_rec(t, t->nodes[node].right, grp, gn, out, olen, ocap);
}

int kek_tree_mincs(const kek_tree_t *t, const int *group_users, int group_n, int **cover_out, int *cover_len) {
  if (!group_users || group_n <= 0) return -1;
  int cap = 8;
  int *out = (int *)malloc(sizeof(int) * (size_t)cap);
  int olen = 0;
  mincs_rec(t, t->root, group_users, group_n, &out, &olen, &cap);
  *cover_out = out;
  *cover_len = olen;
  return 0;
}

int kek_tree_intersect_deepest(const kek_tree_t *t, int user_id, const int *cover, int cover_len,
                               int *node_out) {
  int *path = NULL;
  int plen = 0;
  if (kek_tree_path(t, user_id, &path, &plen) != 0) return -1;
  int best = -1;
  int best_depth = -1;
  for (int i = 0; i < plen; i++) {
    int v = path[i];
    for (int j = 0; j < cover_len; j++)
      if (cover[j] == v) {
        if (i > best_depth) {
          best_depth = i;
          best = v;
        }
      }
  }
  free(path);
  if (best < 0) return -2;
  *node_out = best;
  return 0;
}
