#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <endian.h>

#define BUFSIZE 1024

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
    char *description_en;

    char **headers;
    size_t num_headers;
    FILE *input;
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
    t->database_type = "ipinfo";
    t->description_en = "ipinfo data";
    t->binary_format_major_version = 2;
    t->binary_format_minor_version = 75;
    t->build_epoch = (uint64_t) time(NULL);
    t->num_headers = 0;

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

size_t mmdb_write_primitive_type(mmdb_type_t type, size_t size, void *val, FILE *fp)
{
  unsigned char control = (type <= MMDB_MAP) ? (type << 5) : 0;
  unsigned char ext_type = (type > MMDB_MAP) ? (type - 7) : 0;
  uint32_t size_bytes = 0, nsize = 0;

  /* printf("CONTROL %u, type: %d\n", control, type); */
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

  /* printf("Size: %d, nsize: %d, size_bytes: %d\n", size, nsize, size_bytes); */
  /* printf("Ext type: %d\n", ext_type); */
  /* printf("Control: %u\n", control); */
  fwrite(&control, 1, 1, fp);
  if (ext_type > 0) {
      fwrite(&ext_type, 1, 1, fp);
  }
  if (nsize > 0) {
      size_bytes = htobe32(size_bytes) >> (4-nsize)*8;
      fwrite(&size_bytes, nsize, 1, fp);
  }
  if (val) {
      fwrite(val, size, 1, fp);
  }

  return 1 + nsize + (val ? size : 0);
}

// FIXME
size_t mmdb_write_pointer(size_t size, FILE *fp)
{
  unsigned char control = MMDB_POINTER << 5;
  uint32_t size_bytes = htobe32(size), nsize = 0;

  if (size < 1<<11 /* 2048 */) {
      control |= (htobe32(size) & 0x700) >> 8;
      size_bytes = htobe32(size) & 0xFF;
      nsize = 1;
  } else if (size < 526336) {
      size_bytes = htobe32(size - 2048);
      control |= (1 << 3) | ((size_bytes & 0x70000) >> 8*2);
      nsize = 2;
  } else if (size < 0){
      size_bytes = htobe32(size - 526336);
      control |= (2 << 3) | ((size_bytes & 0x7000000) >> 8*3);
      nsize = 3;
  } else {
      control |= (3 << 3);
      nsize = 4;
  }

  fwrite(&control, 1, 1, fp);
  size_bytes = size_bytes >> (4-nsize)*8;
  fwrite(&size_bytes, nsize, 1, fp);
  return 0;
}

size_t mmdb_write_uint16(uint16_t val, FILE *fp)
{
  val = htobe16(val);
  return mmdb_write_primitive_type(MMDB_UINT16, 2, &val, fp);
}

size_t mmdb_write_uint32(uint32_t val, FILE *fp)
{
  val = htobe32(val);
  return mmdb_write_primitive_type(MMDB_UINT32, 4, &val, fp);
}

size_t mmdb_write_uint64(uint32_t val, FILE *fp)
{
  val = htobe64(val);
  return mmdb_write_primitive_type(MMDB_UINT64, 8, &val, fp);
}

void mmdb_write_metadata(mmdb_tree_t * t, FILE *fp)
{
  fwrite("\xab\xcd\xefMaxMind.com", 14, 1, fp);
  mmdb_write_primitive_type(MMDB_MAP, 9, NULL, fp);

  t->node_count = htobe32(t->node_count);
  mmdb_write_primitive_type(MMDB_STRING, 10, "node_count", fp);
  mmdb_write_uint32(t->node_count, fp);

  mmdb_write_primitive_type(MMDB_STRING, 27, "binary_format_major_version", fp);
  mmdb_write_uint16(t->binary_format_major_version, fp);

  mmdb_write_primitive_type(MMDB_STRING, 27, "binary_format_minor_version", fp);
  mmdb_write_uint16(t->binary_format_minor_version, fp);

  mmdb_write_primitive_type(MMDB_STRING, 11, "build_epoch", fp);
  mmdb_write_uint64(t->build_epoch, fp);

  mmdb_write_primitive_type(MMDB_STRING, 13, "database_type", fp);
  mmdb_write_primitive_type(MMDB_STRING, strlen(t->database_type), t->database_type, fp);

  mmdb_write_primitive_type(MMDB_STRING, 11, "description", fp);
  mmdb_write_primitive_type(MMDB_MAP, 1, NULL, fp);
  mmdb_write_primitive_type(MMDB_STRING, 2, "en", fp);
  mmdb_write_primitive_type(MMDB_STRING, strlen(t->description_en), t->description_en, fp);

  mmdb_write_primitive_type(MMDB_STRING, 10, "ip_version", fp);
  mmdb_write_uint16(t->ip_version, fp);

  mmdb_write_primitive_type(MMDB_STRING, 9, "languages", fp);
  mmdb_write_primitive_type(MMDB_ARRAY, 1, NULL, fp);
  mmdb_write_primitive_type(MMDB_STRING, 2, "en", fp);

  mmdb_write_primitive_type(MMDB_STRING, 11, "record_size", fp);
  mmdb_write_uint16(t->record_size, fp);
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

void mmdb_write_file(mmdb_tree_t *t, FILE *fp)
{
  mmdb_write_tree(t, fp);

  fseek(fp, t->record_size * t->node_count, SEEK_SET);
  fwrite("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, 1, fp);

  mmdb_write_metadata(t, fp);
}

void append_string(char ***arr, size_t *size, char *str)
{
  *size = *size + 1;
  *arr = (char**)realloc(*arr, *size * sizeof(char*));
  (*arr)[*size-1] = str;
}

char read_until_char(char *delimiters, char **str, size_t *size, FILE *fp)
{
  char buf[BUFSIZE], ch;
  size_t written_to_buffer = 0, nbuffers = 0;
  *size = 0;
  while(1) {
      ch = fgetc(fp);
      /* printf("CHAR: %c %u %u\n", ch, *size, written_to_buffer); */
      if(strchr(delimiters, ch) || ch == EOF) {
          *str = realloc(*str, *size+1);
          strncpy(*str+nbuffers*BUFSIZE, buf, written_to_buffer);
          (*str)[*size] = '\0';
          return ch;
      }

      if(written_to_buffer >= BUFSIZE) {
          /* printf("Resetting buffer\n"); */
          *str = realloc(*str, *size+1);
          strncpy(*str+nbuffers*BUFSIZE, buf, written_to_buffer);
          written_to_buffer = 0;
          nbuffers++;
      }

      buf[written_to_buffer++] = ch;
      *size = *size + 1;
  }
}

size_t skip_to_char(char *delimiters, FILE *fp)
{
  char ch;
  size_t count = 0;
  while(1) {
    ch = fgetc(fp);
    count++;
    if(strchr(delimiters, ch) || ch == EOF)
      break;
  }
  return count;
}

void read_input_file(mmdb_tree_t *t, char *fname)
{
  FILE *fp = fopen(fname, "r");
  char *str = NULL;
  char **columns = NULL;
  size_t size = 0, ncolumns = 0, pos = 0;
  t->input = fp;
  t->headers = NULL;
  t->num_headers = 0;
  char ch;
  // Load headers array
  while (1) {
      ch = read_until_char("\t\n", &str, &size, fp);
      pos += size + 1;
      printf("Col name: %s\t\t(%d, %d)\t%d\n", str, size, pos, t->num_headers);
      append_string(&(t->headers), &(t->num_headers), str);
      str = NULL;
      if (ch == '\n')
        break;
  }
  prefix_t prefix;
  printf("Header finished at %d\n", pos);
  while(1) {
      ch = read_until_char("\t\n", &str, &size, fp);

      if (size == 0)
        break;

      pos += size + 1;

      if (ch != '\t') {
        fprintf(stderr, "IP range must be followed by TAB\n");
        exit(1);
      }

      printf("Inserting prefix %s with data %d\n", str, pos);
      parse_prefix(str, &prefix);
      insert_prefix(t, &prefix, pos);

      pos += skip_to_char("\n", fp);
      str[0] = '\0';
      if (ch == EOF)
        break;
  }
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

  /* traverse_pre_order(tree->root, &print_node, NULL); */

  FILE *fp = fopen("./test.mmdb", "w");
  /* mmdb_write_tree(tree, fp); */

  /* mmdb_write_pointer(2049, fp); */
  /* mmdb_write_metadata(tree, fp); */

  read_input_file(tree, "./biz.tsv");
  printf("Node count: %d\n", tree->node_count);

  mmdb_write_file(tree, fp);
  /* fclose(fp); */
}
