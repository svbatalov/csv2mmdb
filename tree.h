#ifndef __MMDB_TREE_H__
#define __MMDB_TREE_H__

mmdb_tree_node_t * make_tree_node();
mmdb_node_data_t * make_data(int val);
mmdb_tree_t* make_tree();
int print_node(mmdb_tree_node_t *t, void* unused);
void traverse_pre_order(mmdb_tree_node_t *t, int (*func)(mmdb_tree_node_t *, void*), void *data);
void insert_prefix(mmdb_tree_t *tree, prefix_t *p, int val);

#endif
