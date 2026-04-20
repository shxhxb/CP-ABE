#ifndef KEK_TREE_H
#define KEK_TREE_H

/*
 * 用户集合上的完全二叉树：每个节点有秘密 theta[v]，用于把「属性组」密钥
 * 拆成仅该组覆盖子树内用户可合解的形式（min 覆盖集 + 与用户路径最深交汇节点）。
 */
#include <pbc/pbc.h>

typedef struct {
  int id;
  int left;
  int right;
  int parent;
  int leaf_user;
} kt_node_t;

typedef struct {
  kt_node_t *nodes;
  element_t *theta; /* 每节点随机指数，调节 KEK 到子树 */
  int n_nodes;
  int root;
  int *leaf_of_user;
  int n_users;
} kek_tree_t;

int kek_tree_build(kek_tree_t *t, pairing_t pairing, int num_users);

void kek_tree_clear(kek_tree_t *t);

int kek_tree_path(const kek_tree_t *t, int user_id, int **path_out, int *path_len);

int kek_tree_mincs(const kek_tree_t *t, const int *group_users, int group_n, int **cover_out, int *cover_len);

int kek_tree_intersect_deepest(const kek_tree_t *t, int user_id, const int *cover, int cover_len,
                               int *node_out);

#endif
