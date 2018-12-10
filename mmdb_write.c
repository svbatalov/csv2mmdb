#include "csv2mmdb.h"
#include "tree.h"
#include "csv_read.h"

size_t safe_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
  size_t written = fwrite(ptr, size, nmemb, stream);
  if (ferror(stream)) {
    perror("safe_write");
    exit(1);
  }
}

size_t mmdb_write_primitive_type(mmdb_type_t type, size_t size, void *val, FILE *fp)
{
  debug_print("write primitive type=%d size=%d\n", type, size);
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

  debug_print("write_wrimitive_type: Control byte: 0x%x; Size: %d, extra bytes of size (%d): size_bytes: %d; Extended type: 0x%x\n",
              control, size, nsize, size_bytes, ext_type);
  /* debug_print("Ext type: 0x%x\n", ext_type); */
  /* debug_print("Control byte: 0x%x\n", control); */

  fseek(fp, 0L, SEEK_CUR);
  safe_fwrite(&control, 1, 1, fp);

  if (ext_type > 0) {
      safe_fwrite(&ext_type, 1, 1, fp);
  }
  if (nsize > 0) {
      size_bytes = htobe32(size_bytes) >> (4-nsize)*8;
      safe_fwrite(&size_bytes, nsize, 1, fp);
  }
  if (val) {
      safe_fwrite(val, size, 1, fp);
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

  safe_fwrite(&control, 1, 1, fp);
  size_bytes = size_bytes >> (4-nsize)*8;
  safe_fwrite(&size_bytes, nsize, 1, fp);
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

size_t mmdb_write_uint64(uint64_t val, FILE *fp)
{
  val = htobe64(val);
  return mmdb_write_primitive_type(MMDB_UINT64, 8, &val, fp);
}

void mmdb_write_metadata(mmdb_tree_t * t, FILE *fp)
{
  safe_fwrite("\xab\xcd\xefMaxMind.com", 14, 1, fp);
  mmdb_write_primitive_type(MMDB_MAP, 9, NULL, fp);

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

size_t mmdb_write_data(mmdb_tree_t *t, mmdb_node_data_t *offset, FILE *out)
{
  if (!offset) {
      debug_print("write_data called with NULL offset\n", 0);
      return 0;
  }

  if(offset->val < 0) {
      // The data is already written
      return 0;
  }
  debug_print("write_data: %d\n", offset->val);
  FILE *in = t->infile;
  char ch, *str = NULL;
  size_t size, idx = 1, bytes_written = 0;
  int newval = -(t->node_count + 16 + t->data_written);

  // Move input pointer to start of the node payload (1st byte of 2nd column)
  debug_print("Moving to offset %d in input file\n", offset->val);
  if(fseek(in, offset->val, SEEK_SET) < 0) {
      perror("mmdb_write_data:");
      exit(1);
  }
  bytes_written += mmdb_write_primitive_type(MMDB_MAP, t->num_headers-1, NULL, out);
  while (1) {
      if(idx >= t->num_headers)
        break;

      debug_print("HEADER %d: [%s](%d)\n", idx, t->headers[idx], strlen(t->headers[idx]));
      bytes_written += mmdb_write_primitive_type(MMDB_STRING, strlen(t->headers[idx]), t->headers[idx], out);

      ch = read_until_char("\t\n", &str, &size, in);
      debug_print("VALUE [%s](%d)\n", str, size);
      bytes_written += mmdb_write_primitive_type(MMDB_STRING, size, str, out);

      /* printf("Col: idx=%d, %s => [%s] Size=%d EndChar=%d\n", idx, t->headers[idx], str, size, ch); */

      /* bytes_written += mmdb_write_primitive_type(MMDB_STRING, strlen(t->headers[idx]), t->headers[idx], out); */
      /* if (ch == '\n' || ch == EOF || idx >= t->num_headers) */
      /*   break; */

      idx++;
      if (str)
        str = NULL;
        /* str[0] = '\0'; */
  }
  debug_print("Reading data at offset %d. %d bytes written\n", offset->val, bytes_written);

  t->data_written += bytes_written;
  offset->val = newval;
  return bytes_written;
}

int mmdb_write_node(mmdb_tree_node_t *node, void* data)
{
  mmdb_tree_t *tree = (mmdb_tree_t*)data;
  size_t data_start_offset = tree->node_count * tree->record_size / 8 * 2 + 16;

  if (!tree) return 1;

  ptr_t l = tree->node_count; /* NO DATA */
  ptr_t r = tree->node_count; /* NO DATA */

  if (node->left) {
      if (node->left->data) {
          fseek(tree->outfile, data_start_offset + tree->data_written, SEEK_SET);
          mmdb_write_data(tree, node->left->data, tree->outfile);
          l = abs(node->left->data->val);
      } else {
          l = node->left->index;
      }
  }

  if (node->right) {
      if (node->right->data) {
          debug_print("Seeking to %d, data_start_offset=%d\n", data_start_offset + tree->data_written, data_start_offset);
          fseek(tree->outfile, data_start_offset + tree->data_written, SEEK_SET);
          mmdb_write_data(tree, node->right->data, tree->outfile);
          r = abs(node->right->data->val);
      } else {
          r = node->right->index;
      }
  }

  ptr_t mmdb_node[2] = {htobe32(l), htobe32(r)};

  debug_print("Seeking to %d\n", sizeof(mmdb_node)*node->index);
  fseek(tree->outfile, sizeof(mmdb_node)*node->index, SEEK_SET);

  debug_print("Writing node %d (%d bytes)\n", node->index, sizeof(mmdb_node));
  safe_fwrite(mmdb_node, sizeof(mmdb_node), 1, tree->outfile);
  return 0;
}

void mmdb_write_tree(mmdb_tree_t *t, FILE *fp)
{
  t->outfile = fp;
  traverse_pre_order(t->root, mmdb_write_node, t);

  size_t offset = t->node_count * t->record_size / 8 * 2 + 16 + t->data_written;
  fseek(fp, offset, SEEK_SET);
  t->data_written += mmdb_write_primitive_type(MMDB_DATA_END, 0, NULL, fp);
}

void mmdb_write_headers(mmdb_tree_t * t, FILE *fp)
{
  size_t offset = t->node_count * t->record_size / 8 * 2 + 16 + t->data_written;
  fseek(fp, offset, SEEK_SET);
  t->header_offset = (size_t*) calloc(t->num_headers, sizeof(size_t));
  int i;
  for(i=0; i<t->num_headers; i++) {
      t->data_written += mmdb_write_primitive_type(MMDB_CACHE, 0, NULL, fp);
      t->header_offset[i] = t->data_written;
      debug_print("header_offset=%d\n", t->header_offset[i]);
      t->data_written += mmdb_write_primitive_type(MMDB_STRING, strlen(t->headers[i]), t->headers[i], fp);
  }
}

void mmdb_write_file(mmdb_tree_t *t, FILE *fp)
{
  mmdb_write_headers(t, fp);
  mmdb_write_tree(t, fp);

  size_t metadata_start_offset = t->node_count * t->record_size / 8 * 2 + 16 + t->data_written;
  fseek(fp, metadata_start_offset, SEEK_SET);
  safe_fwrite("\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16, 1, fp);

  mmdb_write_metadata(t, fp);
}
