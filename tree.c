#include "csv2mmdb.h"

mmdb_tree_node_t * make_tree_node()
{
  static uint32_t index = 0;
  mmdb_tree_node_t *node = (mmdb_tree_node_t*) calloc(1, sizeof(mmdb_tree_t));
  node->index = index++;
  node->data = NULL;
  return node;
}

mmdb_node_data_t * make_data(int val)
{
  mmdb_node_data_t * data = (mmdb_node_data_t*) calloc(1, sizeof(mmdb_node_data_t));
  data->val = val;
  return data;
}

mmdb_tree_t* make_tree()
{
    mmdb_tree_t * t = malloc(sizeof(mmdb_tree_t));
    t->root = NULL; //make_tree_node();
    t->node_count = 0;
    t->record_size = 32;
    t->ip_version = 4;
    t->database_type = "ipinfo";
    t->description_en = "ipinfo data";
    t->binary_format_major_version = 2;
    t->binary_format_minor_version = 0;
    t->build_epoch = (uint64_t) time(NULL);
    t->num_headers = 0;
    t->data_written = 0;
    t->infile = NULL;
    t->outfile = NULL;

    return t;
}

int print_node(mmdb_tree_node_t *t, void* unused)
{
    printf("%d:\t%d | %d [%d]\n", t->index, t->left ? t->left->index : -1, t->right ? t->right->index : -1, t->data ? t->data->val : -1);
    /* if(t->data) return 1; */
    return 0;
}

void traverse_pre_order(mmdb_tree_node_t *t, int (*func)(mmdb_tree_node_t *, void*), void *data)
{
    if (!t) return;
    if( func(t, data) )
      return;
    traverse_pre_order(t->left, func, data);
    traverse_pre_order(t->right, func, data);
}

void insert_prefix(mmdb_tree_t *tree, prefix_t *p, int val)
{
  mmdb_tree_node_t *cur = tree->root, *node;
  mmdb_node_data_t *data = make_data(val);

  int i, bit, counter = 0;
  if (!cur) {
      tree->root = cur = make_tree_node();
      tree->node_count++;
  }

  mmdb_node_data_t *parent_data = NULL;
  for(i=sizeof(p->host)*8 - 1; i>=0; i--) {

      if (cur && cur->data)
        parent_data = cur->data;

      if(counter++ == p->masklen) {
          printf("Inserting data %d to node at bit %d\n", val, sizeof(p->host)*8 -1 - i);
          cur->data = data;
          return;
      }

      bit = (p->host >> i) & 1;
      node = (bit ? cur->right : cur->left);

      if (!node) {
          node = make_tree_node();
          tree->node_count++;
      }

      if (bit) {
          cur->right = node;
          if (parent_data && parent_data->val) {
              printf("Inserting PARENT data %d to left node at bit %d\n", parent_data->val, sizeof(p->host)*8 -1 - i);
              cur->left = cur->left ? cur->left : (tree->node_count++, make_tree_node());
              if (cur->left->data) {
                free(cur->left->data);
              }
              cur->left->data = parent_data;
              cur->data = NULL;
          }
      }
      else {
          cur->left = node;
          if (parent_data && parent_data->val) {
              printf("Inserting PARENT data %d to right node at bit %d\n", parent_data->val, sizeof(p->host)*8 -1 - i);
              cur->right = cur->right ? cur->right : (tree->node_count++, make_tree_node());
              if (cur->right->data) {
                free(cur->right->data);
              }
              cur->right->data = parent_data;
              cur->data = NULL;
          }
      }

      cur = node;
  }
  free(data);
}
