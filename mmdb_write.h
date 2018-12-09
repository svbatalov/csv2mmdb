#ifndef __MMDB_WRITE_H__
#define __MMDB_WRITE_H__

size_t safe_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t mmdb_write_primitive_type(mmdb_type_t type, size_t size, void *val, FILE *fp);
size_t mmdb_write_pointer(size_t size, FILE *fp);
size_t mmdb_write_uint16(uint16_t val, FILE *fp);
size_t mmdb_write_uint32(uint32_t val, FILE *fp);
size_t mmdb_write_uint64(uint64_t val, FILE *fp);
void mmdb_write_metadata(mmdb_tree_t * t, FILE *fp);
size_t mmdb_write_data(mmdb_tree_t *t, mmdb_node_data_t *offset, FILE *out);
int mmdb_write_node(mmdb_tree_node_t *node, void* data);
void mmdb_write_tree(mmdb_tree_t *t, FILE *fp);
void mmdb_write_file(mmdb_tree_t *t, FILE *fp);

#endif
