#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <endian.h>

typedef enum {
    /* Normal types 1-7 (that fit into first 3 bits of control byte) */
    MMDB_POINTER=1, MMDB_STRING, MMDB_DOUBLE, MMDB_BYTES, MMDB_UINT16, MMDB_UINT32, MMDB_MAP,
    /* Extended types */
    MMDB_INT32, MMDB_UINT64, MMDB_UINT128, MMDB_ARRAY, MMDB_CACHE, MMDB_DATA_END, MMDB_BOOL, MMDB_FLOAT
} mmdb_type_t;

typedef uint32_t ptr_t;

typedef struct {
    in_addr_t host;
    uint8_t masklen;
} prefix_t;

typedef struct mmdb_tree {
    struct mmdb_tree *left;
    struct mmdb_tree *right;
    uint32_t index;
    int data;
} mmdb_tree_node_t;

typedef struct {
    mmdb_tree_node_t *root;

    uint32_t node_count;
    uint16_t record_size;
    uint16_t ip_version;
    char *database_type;
    /* char **languages; */
    uint16_t binary_format_major_version;
    uint16_t binary_format_minor_version;
    uint64_t build_epoch;
    /* description; */
} mmdb_tree_t;

typedef struct {
    FILE *file;
    mmdb_tree_t *tree;
} mmdb_writer_data_t;

void parse_prefix(char *ip_str, prefix_t *p)
{
    in_addr_t ip;

    char buf[INET_ADDRSTRLEN + 3];
    char *host_str = strsep(&ip_str, "/");
    inet_pton(AF_INET, host_str, &ip);

    p->host = ntohl(ip);
    
    if (!ip_str) {
        p->masklen = 32;
    } else {
        p->masklen = atoi(ip_str);
    }
}

mmdb_tree_node_t * make_tree_node()
{
  static uint32_t index = 0;
  mmdb_tree_node_t *node = (mmdb_tree_node_t*) calloc(1, sizeof(mmdb_tree_t));
  node->index = index++;
  return node;
}

mmdb_tree_t* make_tree()
{
    mmdb_tree_t * t = malloc(sizeof(mmdb_tree_t));
    t->root = NULL; //make_tree_node();
    t->node_count = 0;
    t->record_size = 32;
    t->ip_version = 4;
    t->database_type = "";
    t->binary_format_major_version = 0;
    t->binary_format_minor_version = 0;
    t->build_epoch = (uint64_t) time(NULL);

    return t;
}

int print_node(mmdb_tree_node_t *t, void* unused)
{
    printf("%d [%d]\n", t->index, t->data);
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

void insert_prefix(mmdb_tree_t *tree, prefix_t *p, int data)
{
  mmdb_tree_node_t *cur = tree->root, *node;

  int i, bit, counter = 0;
  if (!cur) {
      tree->root = cur = make_tree_node();
      tree->node_count++;
  }

  for(i=sizeof(p->host)*8 - 1; i>=0; i--) {

      if(counter++ == p->masklen-1) {
        cur->data = data;
        return;
      }

      bit = (p->host >> i) & 1;
      node = (bit ? cur->right : cur->left);
      if (!node) {
          node = make_tree_node();
          tree->node_count++;
      }

      if (bit)
        cur->right = node;
      else
        cur->left = node;

      cur = node;
  }
}

void mmdb_write_primitive_type(FILE *fp, mmdb_type_t type, size_t size, void *val)
{
  unsigned char control = (type <= MMDB_MAP) ? (type << 5) : 0;
  unsigned char ext_type = (type > MMDB_MAP) ? (type - 7) : 0;
  uint32_t size_bytes = 0, nsize = 0;

  printf("CONTROL %u, type: %d\n", control, type);
  if (size < 29) {
      control |= size;
  } else if (size >= 29 && size < 285) {
      control |= 29;
      nsize = 1;
      size_bytes = size - 29;
  } else if (size >= 285 && size < 65821) {
      control |= 30;
      nsize = 2;
      size_bytes = size - 285;
  } else {
      control |= 31;
      nsize = 3;
      size_bytes = size - 65821;
  }

  printf("Size: %d, nsize: %d, size_bytes: %d\n", size, nsize, size_bytes);
  printf("Ext type: %d\n", ext_type);
  printf("Control: %u\n", control);
  fwrite(&control, 1, 1, fp);
  if (ext_type > 0) {
      fwrite(&ext_type, 1, 1, fp);
  }
  if (nsize > 0) {
      size_bytes = htobe32(size_bytes) >> (4-nsize)*8;
      printf("%d\n", size_bytes);
      fwrite(&size_bytes, nsize, 1, fp);
  }
}
int mmdb_write_node(mmdb_tree_node_t *node, void* data)
{

  mmdb_writer_data_t *d = (mmdb_writer_data_t*) data;
  mmdb_tree_t *tree = d->tree;

  if (!d || !d->tree) return 1;

  ptr_t l = node->left ? node->left->index : tree->node_count; /* NO DATA */
  ptr_t r = node->right ? node->right->index : tree->node_count; /* NO DATA */

  ptr_t mmdb_node[2] = {htobe32(l), htobe32(r)};

  printf("Seeking to %d\n", sizeof(mmdb_node)*node->index);
  fseek(d->file, sizeof(mmdb_node)*node->index, SEEK_SET);

  printf("Writing node %d (%d bytes)\n", node->index, sizeof(mmdb_node));
  fwrite(mmdb_node, sizeof(mmdb_node), 1, d->file);
  return 0;
}

void mmdb_write_tree(mmdb_tree_t *t, FILE *fp)
{
  mmdb_writer_data_t data = {.file = fp, .tree = t};
  traverse_pre_order(t->root, mmdb_write_node, (void*)&data);
}

int main(int argc, char **argv)
{
  prefix_t prefix;
  mmdb_tree_t *tree = make_tree();

  char buf[INET_ADDRSTRLEN+3] = "1.255.0.0";
  /* parse_prefix(buf, &prefix); */
  /* insert_prefix(tree, &prefix, 123456); */

  /* strcpy(buf, "1.2.3.4/24"); */
  /* parse_prefix(buf, &prefix); */
  /* insert_prefix(tree, &prefix, 321); */

  /* strcpy(buf, "1.2.3.4"); */
  /* parse_prefix(buf, &prefix); */
  /* insert_prefix(tree, &prefix, 111); */

  traverse_pre_order(tree->root, &print_node, NULL);

  FILE *fp = fopen("./test.mmdb", "w");
  mmdb_write_tree(tree, fp);
  printf("Node count: %d\n", tree->node_count);

  mmdb_write_primitive_type(fp, MMDB_STRING, 3421264, NULL);
  fclose(fp);
}
